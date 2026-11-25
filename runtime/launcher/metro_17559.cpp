#include "launcher/metro_17559.hpp"
#include "os/dashboard/leaf_17559.hpp"
#include "os/dashboard/memory_leaf_17559.hpp"
#include <stdexcept>
namespace x360::launcher {
Metro17559::Metro17559(){
    if(!dispatch_.register_module("dash_17559",os::dashboard::leaf_bindings_17559())||
       !dispatch_.register_memory_module("dash_17559",os::dashboard::memory_leaf_bindings_17559()))
        throw std::logic_error("invalid Metro 17559 binding manifest");
}
execution::DispatchResult Metro17559::call(abi::Address address,abi::GuestCall& state) const {
    return dispatch_.invoke("dash_17559",address,state,&memory_);
}
}
