//
// Created by sdn on 9/23/20.
//

#ifndef BM_BM_FLOW_CONTEXT_H
#define BM_BM_FLOW_CONTEXT_H

#include <vector>
#include <bm/bm_sim/stateful.h>
#include <bm/bm_sim/headers.h>

namespace bm {

class FlowContext {
public:
  using iterator = std::vector<RegisterArray *>::iterator;
  using const_iterator = std::vector<RegisterArray *>::const_iterator;

  FlowContext(HeaderType *flow_ctx_ht, size_t size);

  //! Access the register at position \p idx, asserts if bad \p idx
  RegisterArray * &operator[](size_t idx) {
    assert(idx < size());
    return flow_registers[idx];
  }

  //! Access the register at position \p idx, throws a std::out_of_range
  //! exception if \p idx is invalid
  RegisterArray * &at(size_t idx) {
    return flow_registers.at(idx);
  }

  iterator begin() { return flow_registers.begin(); }

  const_iterator begin() const { return flow_registers.begin(); }

  iterator end() { return flow_registers.end(); }

  const_iterator end() const { return flow_registers.end(); }

  size_t size() const { return flow_registers.size(); }

private:
  std::vector<RegisterArray *> flow_registers{};
  int nregs{};
};

} // namespace bm
#endif //BM_BM_FLOW_CONTEXT_H
