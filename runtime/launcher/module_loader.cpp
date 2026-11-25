#include "launcher/module_loader.hpp"
#include <utility>
namespace x360::launcher {
LoadResult load_verified_module(machine::AddressSpace& memory,execution::ModuleRegistry& registry,
                               execution::ModuleManifest manifest,std::span<const std::uint8_t> image){
    if(image.size()!=manifest.size)return LoadResult::invalid_image;
    execution::ModuleRegistry staged=registry;
    auto name=manifest.name;
    if(!staged.register_module(std::move(manifest)))return LoadResult::invalid_manifest;
    const auto& m=*staged.module(name);
    for(auto& i:m.imports){
        auto off=std::size_t(i.address-m.base);
        auto b=image.subspan(off,4);
        auto word=(std::uint32_t(b[0])<<24)|(std::uint32_t(b[1])<<16)|(std::uint32_t(b[2])<<8)|b[3];
        if((word>>24)!=static_cast<std::uint8_t>(i.kind)||(word&0xffffu)!=i.ordinal)
            return LoadResult::import_word_mismatch;
    }
    std::vector<machine::RegionMapping> mappings;
    std::size_t pos=0;
    for(auto& s:m.sections){
        auto begin=std::size_t(s.address-m.base);
        if(begin>pos)mappings.push_back({static_cast<abi::Address>(std::uint64_t(m.base)+pos),image.subspan(pos,begin-pos),false});
        mappings.push_back({s.address,image.subspan(begin,s.size),s.writable()});
        pos=begin+s.size;
    }
    if(pos<image.size())mappings.push_back({static_cast<abi::Address>(std::uint64_t(m.base)+pos),image.subspan(pos),false});
    if(!memory.map_batch(mappings))return LoadResult::mapping_conflict;
    registry.swap(staged);
    return LoadResult::loaded;
}
}
