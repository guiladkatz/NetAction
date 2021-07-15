//
// Created by sdn on 9/24/20.
//

#include <bm/bm_sim/flow_context.h>
#include <bm/bm_sim/logger.h>

namespace bm {

FlowContext::FlowContext(HeaderType *flow_ctx_ht, size_t size) {
  for (int i = 0; i < flow_ctx_ht->get_num_fields(); i++) {
    if (flow_ctx_ht->get_field_name(i) == "$valid$"
        || flow_ctx_ht->get_field_name(i) == "_padding_0")
      continue;

    this->nregs++;
  }

  BMLOG_DEBUG("Creating flow context {}, with {} fields of size {}",
      flow_ctx_ht->get_name(), nregs, size);

  flow_registers.reserve(nregs);

  int j = 0;
  for (int i = 0; i < flow_ctx_ht->get_num_fields(); i++) {
    if (flow_ctx_ht->get_field_name(i) == "$valid$"
          || flow_ctx_ht->get_field_name(i) == "_padding_0")
      continue;

    flow_registers.push_back(new RegisterArray(flow_ctx_ht->get_field_name(i),
                                j, size, flow_ctx_ht->get_bit_width(i)));
    BMLOG_DEBUG("Created #{} register array: name={}, bitwidth={}",
                    j, flow_registers[j]->get_name(), flow_ctx_ht->get_bit_width(i));
    j++;
  }
}

} // namespace bm