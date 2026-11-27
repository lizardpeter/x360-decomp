#include "machine/address_space.hpp"
#include <algorithm>
#include <iterator>
namespace x360::machine {
namespace {
constexpr std::uint64_t limit=std::uint64_t{1}<<32;
bool fits(abi::Address base,std::size_t bytes) noexcept { return bytes<=limit-base; }
bool valid_pages(abi::Address base,std::uint32_t size,std::uint32_t page){
    return (page==4096||page==65536)&&base&&size&&!(base%page)&&!(size%page)&&fits(base,size);
}
bool overlaps(std::uint64_t a,std::uint64_t n,std::uint64_t b,std::uint64_t m){
    return a<b+m&&b<a+n;
}
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
        for(auto& [base,res]:reservations_)if(overlaps(r.base,r.bytes.size(),base,res.size))return false;
        pending.emplace(r.base,Region{{r.bytes.begin(),r.bytes.end()},r.writable});
    }
    regions_.merge(pending);
    return true;
}
bool AddressSpace::reserve(abi::Address base,std::uint32_t size,std::uint32_t page){
    if(!valid_pages(base,size,page))return false;
    for(auto& [b,r]:regions_)if(overlaps(base,size,b,r.bytes.size()))return false;
    for(auto& [b,r]:reservations_)if(overlaps(base,size,b,r.size))return false;
    return reservations_.emplace(base,Reservation{base,size,page}).second;
}
std::optional<abi::Address> AddressSpace::reserve_first(abi::Address lower,std::uint64_t upper,
                                                        std::uint32_t size,std::uint32_t page){
    if(!valid_pages(lower,size,page)||upper>limit||upper<=lower||size>upper-lower)return {};
    std::vector<std::pair<std::uint64_t,std::uint64_t>> occupied;
    for(auto& [b,r]:regions_)occupied.emplace_back(b,std::uint64_t(b)+r.bytes.size());
    for(auto& [b,r]:reservations_)occupied.emplace_back(b,std::uint64_t(b)+r.size);
    std::sort(occupied.begin(),occupied.end());
    std::uint64_t candidate=lower;
    for(auto [begin,end]:occupied){
        if(end<=candidate)continue;
        if(begin>=upper||(begin>=candidate&&size<=begin-candidate))break;
        candidate=(end+page-1)&~std::uint64_t(page-1);
        if(candidate>=upper||size>upper-candidate)return {};
    }
    if(candidate>=upper||size>upper-candidate)return {};
    auto address=static_cast<abi::Address>(candidate);
    if(!reserve(address,size,page))return {};
    return address;
}
std::optional<Reservation> AddressSpace::reservation(abi::Address address) const noexcept{
    auto it=reservations_.upper_bound(address);
    if(it==reservations_.begin())return {};
    --it;auto r=it->second;
    if(std::uint64_t(address)-r.base>=r.size)return {};
    return r;
}
bool AddressSpace::commit(abi::Address base,std::uint32_t size,bool writable){
    auto r=reservation(base);
    if(!r||!valid_pages(base,size,r->page_size)||
       std::uint64_t(base)+size>std::uint64_t(r->base)+r->size||size>64u*1024*1024)return false;
    for(auto& [b,region]:regions_)if(overlaps(base,size,b,region.bytes.size()))return false;
    // All new pages are deterministically zeroed; no host allocation content leaks.
    return regions_.emplace(base,Region{std::vector<std::uint8_t>(size),writable}).second;
}
bool AddressSpace::decommit(abi::Address base,std::uint32_t size){
    auto r=reservation(base);
    if(!r||!valid_pages(base,size,r->page_size)||std::uint64_t(base)+size>std::uint64_t(r->base)+r->size)return false;
    const auto end=std::uint64_t(base)+size;
    std::vector<abi::Address> removed;
    std::map<abi::Address,Region> fragments;
    // Stage all replacements before changing mappings. A partially decommitted
    // region keeps its unaffected bytes and permissions.
    for(auto& [b,region]:regions_){
        auto e=std::uint64_t(b)+region.bytes.size();
        if(!overlaps(base,size,b,region.bytes.size()))continue;
        removed.push_back(b);
        if(b<base)fragments.emplace(b,Region{{region.bytes.begin(),region.bytes.begin()+(base-b)},region.writable});
        if(e>end)fragments.emplace(static_cast<abi::Address>(end),Region{{region.bytes.begin()+(end-b),region.bytes.end()},region.writable});
    }
    for(auto b:removed)regions_.erase(b);
    regions_.merge(fragments);return true;
}
bool AddressSpace::release(abi::Address base){
    auto it=reservations_.find(base);if(it==reservations_.end())return false;
    auto end=std::uint64_t(base)+it->second.size;
    for(auto pos=regions_.lower_bound(base);pos!=regions_.end()&&pos->first<end;)
        pos=regions_.erase(pos);
    reservations_.erase(it);return true;
}
std::optional<bool> AddressSpace::page_writable(abi::Address address) const noexcept{
    auto it=regions_.upper_bound(address);
    if(it==regions_.begin())return {};
    --it;
    if(std::uint64_t(address)-it->first>=it->second.bytes.size())return {};
    return it->second.writable;
}
bool AddressSpace::protect(abi::Address base,std::uint32_t size,bool writable){
    auto r=reservation(base);
    if(!r||!valid_pages(base,size,r->page_size)||
       std::uint64_t(base)+size>std::uint64_t(r->base)+r->size||
       !accessible(base,size,false))return false;
    const auto end=std::uint64_t(base)+size;
    std::vector<abi::Address> removed;
    std::map<abi::Address,Region> fragments;
    for(const auto& [b,region]:regions_){
        const auto e=std::uint64_t(b)+region.bytes.size();
        if(!overlaps(base,size,b,region.bytes.size()))continue;
        if(region.writable==writable)continue;
        removed.push_back(b);
        const auto lo=std::max<std::uint64_t>(b,base),hi=std::min(e,end);
        if(b<lo)fragments.emplace(b,Region{{region.bytes.begin(),region.bytes.begin()+(lo-b)},region.writable});
        fragments.emplace(static_cast<abi::Address>(lo),Region{{region.bytes.begin()+(lo-b),region.bytes.begin()+(hi-b)},writable});
        if(hi<e)fragments.emplace(static_cast<abi::Address>(hi),Region{{region.bytes.begin()+(hi-b),region.bytes.end()},region.writable});
    }
    for(auto b:removed)regions_.erase(b);
    regions_.merge(fragments);
    return true;
}
bool AddressSpace::accessible(abi::Address address,std::size_t size,bool write) const noexcept{
    if(!size||!fits(address,size))return false;
    std::uint64_t cursor=address,end=cursor+size;
    auto it=regions_.upper_bound(address);
    if(it==regions_.begin())return false;
    --it;
    while(cursor<end){
        if(it==regions_.end()||cursor<it->first||(write&&!it->second.writable))return false;
        const auto region_end=std::uint64_t(it->first)+it->second.bytes.size();
        if(cursor>=region_end)return false;
        cursor=std::min(end,region_end);
        ++it;
    }
    return true;
}
bool AddressSpace::writable_range(abi::Address address,std::size_t size) const noexcept{
    return accessible(address,size,true);
}
bool AddressSpace::read(abi::Address address,std::span<std::uint8_t> bytes) const noexcept{
    if(!accessible(address,bytes.size(),false))return false;
    auto it=std::prev(regions_.upper_bound(address));
    std::uint64_t cursor=address;
    std::size_t copied=0;
    while(copied<bytes.size()){
        const auto offset=static_cast<std::size_t>(cursor-it->first);
        const auto n=std::min(bytes.size()-copied,it->second.bytes.size()-offset);
        std::copy_n(it->second.bytes.begin()+offset,n,bytes.begin()+copied);
        copied+=n;cursor+=n;++it;
    }
    return true;
}
bool AddressSpace::write(abi::Address address,std::span<const std::uint8_t> bytes) noexcept{
    if(!accessible(address,bytes.size(),true))return false;
    auto it=std::prev(regions_.upper_bound(address));
    std::uint64_t cursor=address;
    std::size_t copied=0;
    while(copied<bytes.size()){
        const auto offset=static_cast<std::size_t>(cursor-it->first);
        const auto n=std::min(bytes.size()-copied,it->second.bytes.size()-offset);
        std::copy_n(bytes.begin()+copied,n,it->second.bytes.begin()+offset);
        copied+=n;cursor+=n;++it;
    }
    return true;
}
}
