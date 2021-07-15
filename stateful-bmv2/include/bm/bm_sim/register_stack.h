//
// Created by sdn on 10/7/20.
//

#ifndef BM_BM_REGISTER_STACK_H
#define BM_BM_REGISTER_STACK_H

#include "stateful.h"

namespace bm {

class RegisterStack : public RegisterArray {
public:
  RegisterStack(const std::string &name, p4object_id_t id,
                size_t size, int bitwidth);

  uint pop();

  void push(Data &data);

  bool is_empty() const { return idx == size(); };

  bool is_full() const { return idx == 0; };

private:
  uint idx{};
};

}

#endif //BM_BM_REGISTER_STACK_H
