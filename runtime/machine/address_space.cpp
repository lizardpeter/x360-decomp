#include "machine/address_space.hpp"
#include <algorithm>
#include <iterator>
namespace x360::machine {
namespace {
constexpr std::uint64_t limit=std::uint64_t{1}<<32;
bool fits(abi::Address base,std::size_t bytes) noexcept { return bytes<=limit-base; }
}
bool AddressSpace::map(abi::Address base,std::span<const std::uint8_t> bytes,bool writable) {
    const RegionMapping one{base,bytes,writable};
    return map_batch(std::span(&one,1));
}
bool AddressSpace::map_batch(std::span<const RegionMapping> regions){
    if(regions.empty())return false;
    std::map<abi::Address,Region> pending;
    auto available=[](const auto& map,abi::Address base,std::size_t size){
        auto next=map.lower_bound(base);
        if(next!=map.end()&&std::uint64_t(base)+size>next->first)return false;
        if(next!=map.begin()){
            auto prev=std::prev(next);
            if(std::uint64_t(prev->first)+prev->second.bytes.size()>base)return false;
        }
        return true;
    };
    for(auto& r:regions){
        if(r.bytes.empty()||!fits(r.base,r.bytes.size())||
           !available(regions_,r.base,r.bytes.size())||!available(pending,r.base,r.bytes.size()))return false;
        pending.emplace(r.base,Region{{r.bytes.begin(),r.bytes.end()},r.writable});
    }
    regions_.merge(pending);
    return true;
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
