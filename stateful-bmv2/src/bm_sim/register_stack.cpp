//
// Created by sdn on 10/7/20.
//

#include <bm/bm_sim/register_stack.h>
#include <include/bm/bm_sim/logger.h>

namespace bm {

RegisterStack::RegisterStack(const std::string &name,
                             p4object_id_t id,
                             size_t size, int bitwidth)
      : RegisterArray(name, id, size, bitwidth) {
  idx = 0;

  int i = size - 1;
  for (auto & reg : *this) {
    reg.set(i); i--;
  }
}

uint
RegisterStack::pop() {
  if (idx < size()) {
    return this->at(idx++).get_uint();
  } else {
    BMLOG_DEBUG("Error on popping from stack")
    return 0;
  }
}

void
RegisterStack::push(Data &data) {
  if (idx < size()) {
    this->at(--idx).set(data);
  } else {
    BMLOG_DEBUG("Error on pushing to stack")
  }
}

} //namespace bm