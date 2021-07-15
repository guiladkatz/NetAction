/* Copyright 2013-present Barefoot Networks, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Antonin Bas (antonin@barefootnetworks.com)
 *
 */

#include <bm/bm_sim/meters.h>
#include <bm/bm_sim/logger.h>
#include <bm/bm_sim/packet.h>

#include <algorithm>
#include <vector>
#include <string>

namespace bm {

using MeterErrorCode = Meter::MeterErrorCode;

using ticks = std::chrono::microseconds;  // better with nanoseconds ?
using std::chrono::duration_cast;

namespace {

Meter::clock::time_point time_init = Meter::clock::now();

}  // namespace

MeterErrorCode
Meter::set_rate(size_t idx, const rate_config_t &config) {
  MeterRate &rate = rates[idx];
  rate.valid = true;
  rate.info_rate = config.info_rate;
  rate.burst_size = config.burst_size;
  rate.tokens = config.burst_size;
  rate.tokens_last = 0u;
  rate.color = (idx + 1);
  if (idx > 0) {
    MeterRate &prev_rate = rates[idx - 1];
    if (prev_rate.info_rate > rate.info_rate) return INVALID_INFO_RATE_VALUE;
  }
  return SUCCESS;
}

MeterErrorCode
Meter::set_ewma_rate(uint64_t window_size) {
  ewma.window_size = window_size;
  ewma.current_slot_ts = window_size;
  ewma.configured = true;
  if (ewma.window_size == 0) {
    ewma.window_size = 1000000u;
    ewma.current_slot_ts = 1000000u;
    return INVALID_INFO_RATE_VALUE;
  }

  return SUCCESS;
}

MeterErrorCode
Meter::reset_rates() {
  auto lock = unique_lock();
  for (MeterRate &rate : rates) {
    rate.valid = false;
  }
  configured = false;
  return SUCCESS;
}

Meter::color_t
Meter::execute(const Packet &pkt, color_t pre_color) {
  color_t packet_color = 0;

  if (!configured) return packet_color;

  clock::time_point now = clock::now();
  int64_t micros_since_init = duration_cast<ticks>(now - time_init).count();

  auto lock = unique_lock();

  /* I tried to make this as accurate as I could. Everything is computed
     compared to a single time point (init). I do not use the interval since
     last update, because it would require multiple consecutive
     approximations. Maybe this is an overkill or I am underestimating the code
     I wrote for BMv1.
     The only thing that could go wrong is if tokens_since_init grew too large,
     but I think it would take years even at high throughput */
  for (MeterRate &rate : rates) {
    uint64_t tokens_since_init =
      static_cast<uint64_t>(micros_since_init * /*rate.info_rate **/ pkt.get_ingress_length());
    assert(tokens_since_init >= rate.tokens_last);
    size_t new_tokens = tokens_since_init - rate.tokens_last;
    rate.tokens_last = tokens_since_init;
    //rate.tokens = std::min(rate.tokens + new_tokens, rate.burst_size);
    rate.tokens += new_tokens;

    BMLOG_DEBUG("New Tokens are: {}", new_tokens)
    BMLOG_DEBUG("Rate is: {}", new_tokens/1000000L)

    size_t input = (type == MeterType::PACKETS) ? 1u : pkt.get_ingress_length();

    if (rate.tokens < input) {
      packet_color = rate.color;
      break;
    } else {
      rate.tokens -= input;
    }
  }

  return std::max(pre_color, packet_color);
}

uint64_t
Meter::execute_ewma(const Packet &pkt, uint64_t current_sample) {
  clock::time_point now = clock::now();
  uint64_t ts_now = duration_cast<ticks>(now - time_init).count();

  auto lock = unique_lock();

  (void)pkt;

  if (ts_now <= ewma.current_slot_ts) {
    ewma.current_slot_samples += current_sample;
    BMLOG_DEBUG("in first case, curr_slot_sam = {}", ewma.current_slot_samples)
  } else if (ts_now >= ewma.current_slot_ts &&
             ts_now < ewma.current_slot_ts + ewma.window_size) {

    ewma.ewma_res = 0.75 * (double) ewma.current_slot_samples +
                    0.25 * (double) ewma.ewma_res;

    ewma.current_slot_samples = current_sample;
    ewma.current_slot_ts += ewma.window_size;

    BMLOG_DEBUG("in second case, res = {}", ewma.ewma_res)
  }
  else {
    // if (ewma.current_slot_ts > 0 ) cannot be = 0, initialized to ewma.window_size
    ewma.current_slot_ts += ewma.window_size * ((ts_now / ewma.current_slot_ts) + 1);
    ewma.current_slot_samples = current_sample;
    ewma.ewma_res = 0;
    BMLOG_DEBUG("in third case, res = {}", ewma.ewma_res)
  }
  return ewma.ewma_res;
}

void
Meter::serialize(std::ostream *out) const {
  auto lock = unique_lock();
  (*out) << configured << "\n";
  if (configured) {
    for (const auto &rate : rates)
      (*out) << rate.info_rate << " " << rate.burst_size << "\n";
  }
}

void
Meter::deserialize(std::istream *in) {
  auto lock = unique_lock();
  (*in) >> configured;
  if (configured) {
    for (size_t i = 0; i < rates.size(); i++) {
      rate_config_t config;
      (*in) >> config.info_rate;
      (*in) >> config.burst_size;
      set_rate(i, config);
    }
  }
}

void
Meter::reset_global_clock() {
  time_init = Meter::clock::now();
}

std::vector<Meter::rate_config_t>
Meter::get_rates() const {
  std::vector<rate_config_t> configs;
  auto lock = unique_lock();
  if (!configured) return configs;
  // elegant but probably not the most efficient
  for (const MeterRate &rate : rates)
    configs.push_back(rate_config_t::make(rate.info_rate, rate.burst_size));
  std::reverse(configs.begin(), configs.end());
  return configs;
}


MeterArray::MeterArray(const std::string &name, p4object_id_t id,
                       MeterType type, size_t rate_count, size_t size)
    : NamedP4Object(name, id) {
  meters.reserve(size);
  for (size_t i = 0; i < size; i++)
    meters.emplace_back(type, rate_count);
}

MeterArray::color_t
MeterArray::execute_meter(const Packet &pkt, size_t idx, color_t pre_color) {
  BMLOG_DEBUG_PKT(pkt, "Executing meter {}[{}]", get_name(), idx);
  return meters[idx].execute(pkt, pre_color);
}

uint64_t
MeterArray::execute_ewma_meter(const Packet &pkt, size_t idx, uint64_t current_sample) {
  BMLOG_DEBUG_PKT(pkt, "Executing ewma meter {}[{}]", get_name(), idx);
  return meters[idx].execute_ewma(pkt, current_sample);
}

MeterArray::MeterErrorCode
MeterArray::set_rates(const std::vector<rate_config_t> &configs) {
  return set_rates(configs.begin(), configs.end());
}

MeterArray::MeterErrorCode
MeterArray::set_rates(const std::initializer_list<rate_config_t> &configs) {
  return set_rates(configs.begin(), configs.end());
}

MeterArray::MeterErrorCode
MeterArray::set_ewma_rates(uint64_t window_size) {
  for (auto & m : meters) {
    MeterErrorCode rc = m.set_ewma_rate(window_size);
    if (rc != Meter::SUCCESS)
      return rc;
  }
  return Meter::SUCCESS;
}

void
MeterArray::reset_state() {
  for (auto &m : meters) m.reset_rates();
}

void
MeterArray::serialize(std::ostream *out) const {
  for (const auto &m : meters) m.serialize(out);
}

void
MeterArray::deserialize(std::istream *in) {
  for (auto &m : meters) m.deserialize(in);
}

}  // namespace bm
