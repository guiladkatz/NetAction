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

#include <bm/bm_sim/stateful_tables.h>
#include <bm/bm_sim/logger.h>
#include "bm/bm_sim/match_tables.h"
#include <bm/bm_sim/core/primitives.h>


#include <string>
#include <bm/bm_sim/flow_context.h>

namespace bm {

#define HANDLE_INTERNAL(h) (h & 0x00ffffff)

  namespace {

template <typename V>
std::unique_ptr<MatchUnitAbstract<V> >
create_match_unit(const size_t size,
                  const MatchKeyBuilder &match_key_builder,
                  LookupStructureFactory *lookup_factory) {
  using MUExact = MatchUnitExact<V>;

  std::unique_ptr<MatchUnitAbstract<V> > match_unit;
  match_unit = std::unique_ptr<MUExact>(
      new MUExact(size, match_key_builder, lookup_factory));
  return match_unit;
}

}  // namespace

FlowTable::FlowTable(
    const std::string &name, p4object_id_t id,
    std::unique_ptr<MatchUnitAbstract<ActionEntry> > match_unit,
    const std::vector<MatchKeyBuilder> &match_key_builders, bool with_counters,
    bool with_ageing, uint64_t idle_timeout)
    : MatchTableAbstract(name, id, with_counters, with_ageing,
                         match_unit.get()),
      match_unit(std::move(match_unit)),
      match_key_builders(match_key_builders),
      idle_timeout(idle_timeout) { }


std::unique_ptr<FlowTable>
FlowTable::create(const std::string &name,
                  p4object_id_t id, size_t size,
                  const std::vector<MatchKeyBuilder> &match_key_builders_,
                  LookupStructureFactory *lookup_factory,
                  bool with_counters, bool with_ageing, uint64_t idle_timeout) {
  std::unique_ptr<MatchUnitAbstract<ActionEntry> > match_unit_ =
      create_match_unit<ActionEntry>(size, match_key_builders_[0], lookup_factory);

  return std::unique_ptr<FlowTable>(
      new FlowTable(name, id, std::move(match_unit_), match_key_builders_,
                    with_counters, with_ageing, idle_timeout));
}

MatchErrorCode
FlowTable::add_entry(const std::vector<MatchKeyParam> &match_key,
                     ActionEntry action,  // move it
                      entry_handle_t *handle) {
  MatchErrorCode rc;

  {
    auto lock = lock_write();

    rc = match_unit->add_entry(
        match_key,
        action,
        handle);
  }

  if (rc == MatchErrorCode::SUCCESS) {
    BMLOG_DEBUG("Entry {} added to table '{}'", HANDLE_INTERNAL(*handle), get_name());
    BMLOG_DEBUG(dump_entry_string(*handle));
  } else {
    BMLOG_ERROR("Error when trying to add entry to table '{}'", get_name());
  }

  return rc;
}

MatchErrorCode
FlowTable::get_action_entry(entry_handle_t handle, const ActionEntry **action) {
  MatchErrorCode rc;

  {
    auto lock = lock_read();

    rc = match_unit->get_value(handle, action);
  }

  if (rc == MatchErrorCode::SUCCESS) {
    BMLOG_DEBUG(dump_entry_string(handle));
    last_handle = handle;
  } else {
    BMLOG_ERROR("Error when trying to get entry to table '{}'", get_name());
  }

  return rc;
}

std::vector<FlowTable::Entry>
FlowTable::get_entries() const  {
    auto lock = lock_read();

    std::vector<Entry> entries(get_num_entries());
    size_t idx = 0;
    for (auto it = match_unit->handles_begin(); it != match_unit->handles_end();
         it++) {
        MatchErrorCode rc = get_entry_(*it, &entries[idx++]);
        _BM_UNUSED(rc);
        assert(rc == MatchErrorCode::SUCCESS);
    }

    return entries;
}

MatchErrorCode
FlowTable::get_entry_(entry_handle_t handle, Entry *entry) const {
    const ActionEntry *action_entry;
    MatchErrorCode rc = match_unit->get_entry(handle, &entry->match_key,
                                              &action_entry, &entry->priority);
    if (rc != MatchErrorCode::SUCCESS) return rc;

    entry->handle = handle;
    entry->action_fn = action_entry->action_fn.get_action_fn();
    entry->action_data = action_entry->action_fn.get_action_data();

    set_entry_common_info(entry);

    return MatchErrorCode::SUCCESS;
}

MatchErrorCode
FlowTable::get_entry_from_key(const std::vector<MatchKeyParam> &match_key,
                               Entry *entry, int priority) const {
  auto lock = lock_read();
  entry_handle_t handle;
  const auto rc = match_unit->retrieve_handle(match_key, &handle, priority);
  if (rc != MatchErrorCode::SUCCESS) return rc;
  return get_entry_(handle, entry);
}

MatchErrorCode
FlowTable::get_entry(entry_handle_t handle, Entry *entry) const  {
    auto lock = lock_read();
    return get_entry_(handle, entry);
}

MatchErrorCode
FlowTable::delete_entry(entry_handle_t handle) {
  MatchErrorCode rc;

  {
    auto lock = lock_write();
    rc = match_unit->delete_entry(handle);
  }

  if (rc == MatchErrorCode::SUCCESS) {
    BMLOG_DEBUG("Removed entry {} from table '{}'", HANDLE_INTERNAL(handle), get_name());
  } else {
    BMLOG_ERROR("Error when trying to remove entry {} from table '{}'",
                HANDLE_INTERNAL(handle), get_name());
  }

  return rc;
}

const ActionEntry &
FlowTable::lookup(const Packet &pkt, bool *hit, entry_handle_t *handle, const ControlFlowNode **next_node) {
  ByteContainer key;
  uint flow_key_id = pkt.get_phv()->
          get_field("standard_metadata.use_flow_key")
          .get_uint();

  if (flow_key_id >= match_key_builders.size()) {
    BMLOG_ERROR("Requested flow key number does not exist");
    exit(EXIT_FAILURE);
  }

  const MatchKeyBuilder &key_builder = match_key_builders[flow_key_id];

  key_builder(*pkt.get_phv(), &key);

  BMLOG_DEBUG("in lookup... the key is: {}", key.to_hex())

  MatchUnitAbstract<ActionEntry>::MatchUnitLookup res = match_unit->lookup_key(key);
  *hit = res.found();
  *handle = res.handle;

  const ActionEntry *entry;
  if (*hit) {
    BMLOG_DEBUG("Entry found, handle is {}", HANDLE_INTERNAL(*handle))
    entry = res.value;
  } else {
    // Entry not found, we must add a new one with some policy (e.g. LRU)
    BMLOG_DEBUG("Entry not found! Inserting it")
    std::vector<MatchKeyParam> match_key{};

    key_builder.get_match_key_params(*pkt.get_phv(), &match_key);

    entry = new ActionEntry(default_default_entry);

    //TODO: check result of insertion, handle some eviction policy
    MatchErrorCode rc = add_entry(match_key, *entry, handle);

    if (rc == MatchErrorCode::TABLE_FULL) {
      uint64_t lowest = 0;
      entry_handle_t entry_to_delete = 0;

      for (auto tmp = handles_begin(); tmp != handles_end(); tmp++) {
        MatchUnit::EntryMeta &entry_meta = match_unit->get_entry_meta(*tmp);

        if (entry_meta.ts.get_ms() <= lowest || lowest == 0) {
          lowest = entry_meta.ts.get_ms();
          entry_to_delete = *tmp;
        }
      }
      delete_entry(entry_to_delete);

      // retry the insertion
      rc = add_entry(match_key, *entry, handle);
    }

    (void)rc;
  }
  // idle timeout
  if (with_ageing) {
    BMLOG_DEBUG("Set entry idle timeout to {} ms", idle_timeout)
    set_entry_ttl(*handle, idle_timeout);
  }

  if (with_meters) {
    // apply meter
    auto target_f = pkt.get_phv()->get_field(
        meter_target_header, meter_target_offset);
    Meter &meter = match_unit->get_meter(*handle);
    target_f.set(meter.execute(pkt));
  }

  *next_node = entry->next_node;

  this->last_handle = *handle;

  //BMLOG_DEBUG("Next node is {}", *next_nodeget_name());
  return *entry;
}


StatefulTable::StatefulTable(
  const std::string &name, p4object_id_t id,
  std::unique_ptr<FlowTable> match_table,
  std::unique_ptr<FlowContext> flow_context)
  : ControlFlowNode(name, id),
    match_table(std::move(match_table)),
    flow_context(std::move(flow_context)) { }

std::string
get_flow_ctx_name(std::string table_name) {
  std::vector<std::string> split;
  std::istringstream iss(table_name);
  std::string segment;

  while (std::getline(iss, segment, '.')) {
    split.push_back(segment);
  }

  return split[1] + "_ctx";
}

void
StatefulTable::delete_entry(entry_handle_t handle) {
  match_table->delete_entry(handle);

  for (size_t idx = 0; idx < flow_context->size(); idx++) {
    // set the value in the flow context to the corresponding field
    flow_context->at(idx)->at(HANDLE_INTERNAL(handle)).set(0);
  }
}

const ControlFlowNode *
StatefulTable::operator()(Packet *pkt) const {
  entry_handle_t handle;
  bool hit;
  const ControlFlowNode *next_node;

  BMLOG_TRACE_PKT(*pkt, "Applying stateful table '{}'", get_name());

  // returns default entry (and action) in any case
  const ActionEntry &action_entry = match_table->lookup(*pkt, &hit, &handle, &next_node);

  if (hit) {
    // extract the flow context normally
    // insert it in the parsed flow_ctx_hdr (set valid and write the fields)
    set_flow_context(pkt, HANDLE_INTERNAL(handle));
  } else {
    // initialize the parsed flow_ctx_hdr: set valid and write 0 to the fields
    auto flow_ctx_hdr = &pkt->get_phv()->get_header(
        get_flow_ctx_name(get_name()));
    flow_ctx_hdr->mark_valid();
    flow_ctx_hdr->reset();
  }

  action_entry.action_fn(pkt);

  return next_node;
}

void
StatefulTable::apply_timer(Packet *pkt) {
  for (auto it = match_table->handles_begin();
          it != match_table->handles_end(); it++) {
    BMLOG_DEBUG("[StatefulTable::apply_timer()] in handles loop,"
                "handle is {}", *it)

    set_flow_context(pkt, HANDLE_INTERNAL(*it));

    //Apply the pipeline of timer actions
    const ActionEntry *action;
      match_table->get_action_entry(*it, &action);

    auto node = action->next_node;

    action->action_fn(pkt);

    while (node) {
      if (pkt->is_marked_for_exit())
        break;

      node = (*node)(pkt);

      if (pkt->update_flow_context())
        this->update_flow_context(pkt->get_phv());
    }
  }
}

void
StatefulTable::update_flow_context(PHV *phv) const {
  Header *flow_ctx_hdr;

  BMLOG_DEBUG("Updating the flow context")

  flow_ctx_hdr = &phv->get_header(get_flow_ctx_name(get_name()));

  entry_handle_t handle = match_table->get_last_handle();

  for (size_t idx = 0; idx < flow_context->size(); idx++) {
    // maybe move it in another place
    flow_ctx_hdr->get_field(idx).set_arith(true);
    // set the value in the flow context to the corresponding field
    uint value = flow_ctx_hdr->get_field(idx).get_uint();

    flow_context->at(idx)->at(HANDLE_INTERNAL(handle)).set(value);

    BMLOG_DEBUG("Setting {} with {}, value = {}",
                flow_context->at(idx)->get_name(),
                flow_ctx_hdr->get_field_name(idx), value)
  }

  flow_ctx_hdr->mark_invalid();
  phv->get_field("standard_metadata.update_flow_ctx").set(false);
}

void
StatefulTable::set_flow_context(Packet *pkt, entry_handle_t handle) const {
  auto flow_ctx_header = &pkt->get_phv()->get_header(
      get_flow_ctx_name(get_name()));

  flow_ctx_header->mark_valid();

  // set the flow context with the one of the current entry
  for (size_t idx = 0; idx < flow_context->size(); idx++) {
    // set the value in the flow context to the corresponding field
    uint value = flow_context->at(idx)->at(HANDLE_INTERNAL(handle)).get_uint();

    flow_ctx_header->get_field(idx).set(value);

    BMLOG_DEBUG("[Set Flow Context] Setting {} with {}, value = {}",
                flow_context->at(idx)->get_name(), flow_ctx_header->get_field_name(idx), value)
  }
}

std::string
StatefulTable::dump_flow_context(entry_handle_t handle) const {
  std::string dump;
  // set the flow context with the one of the current entry
  for (size_t idx = 0; idx < flow_context->size(); idx++) {
    dump.append(flow_context->at(idx)->get_name() + ":\t" +
                    std::to_string(flow_context->at(idx)->at(HANDLE_INTERNAL(handle)).get_uint()) + "\n");
  }
  return dump;
}

void
FlowTable::reset_state_(bool reset_default_entry) { (void)reset_default_entry; }

void
FlowTable::serialize_(std::ostream *out) const { (void)out; }

void
FlowTable::deserialize_(std::istream *in, const P4Objects &objs) { (void)in; (void)objs; }

MatchErrorCode
FlowTable::dump_entry_(std::ostream *out,
                       entry_handle_t handle) const { (void)out; (void)handle; return MatchErrorCode::ERROR; }

void
FlowTable::set_default_default_entry_() {}

}  // namespace bm
