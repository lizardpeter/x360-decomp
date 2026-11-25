#include "machine/address_space.hpp"
#include <algorithm>
#include <iterator>
namespace x360::machine {
namespace {
constexpr std::uint64_t limit=std::uint64_t{1}<<32;
bool fits(abi::Address base,std::size_t bytes) noexcept { return bytes<=limit-base; }
}
bool AddressSpace::map(abi::Address base,std::span<const std::uint8_t> bytes,bool writable) {
    if(bytes.empty()||!fits(base,bytes.size()))return false;
    auto next=regions_.lower_bound(base);
    if(next!=regions_.end()&&std::uint64_t(base)+bytes.size()>next->first)return false;
    if(next!=regions_.begin()){
        auto prev=std::prev(next);
        if(std::uint64_t(prev->first)+prev->second.bytes.size()>base)return false;
    }
    return regions_.emplace(base,Region{{bytes.begin(),bytes.end()},writable}).second;
}
bool AddressSpace::read(abi::Address address,std::span<std::uint8_t> bytes) const noexcept {
    if(bytes.empty()||!fits(address,bytes.size()))return false;
    auto it=regions_.upper_bound(address);
    if(it==regions_.begin())return false;
    --it;
    auto offset=std::uint64_t(address)-it->first;
    if(offset>it->second.bytes.size()||bytes.size()>it->second.bytes.size()-offset)return false;
    std::copy_n(it->second.bytes.begin()+offset,bytes.size(),bytes.begin());
    return true;
}
bool AddressSpace::write(abi::Address address,std::span<const std::uint8_t> bytes) noexcept {
    if(bytes.empty()||!fits(address,bytes.size()))return false;
    auto it=regions_.upper_bound(address);
    if(it==regions_.begin())return false;
    --it;
    auto offset=std::uint64_t(address)-it->first;
    if(!it->second.writable||offset>it->second.bytes.size()||bytes.size()>it->second.bytes.size()-offset)return false;
    std::copy(bytes.begin(),bytes.end(),it->second.bytes.begin()+offset);
    return true;
}
}
