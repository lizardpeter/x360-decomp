#include "formats/xui_timeline.hpp"
namespace x360::formats::xui {
namespace {
std::uint16_t next(Bytes b,std::size_t& p){
    if(p>=b.size())throw FormatError("truncated NAME integer");
    unsigned x=b[p++];
    if(x>=0xf0){
        if(p>=b.size())throw FormatError("truncated NAME extended integer");
        x=((x&15)<<8)|b[p++];
        if(x<0xf0)throw FormatError("noncanonical NAME integer");
    }
    return static_cast<std::uint16_t>(x);
}
std::uint16_t index(Bytes b,std::size_t& p,std::size_t count){
    auto i=next(b,p);
    if(!i||i>count)throw FormatError("NAME string index out of range");
    return i;
}
}
TimelineNames TimelineNames::parse(const Scene& scene){
    TimelineNames out;auto b=scene.section("NAME");if(!b)return out;
    if(scene.version()!=8)throw FormatError("unsupported NAME version");
    std::size_t p=0;
    while(p<b->size()){
        TimelineMarker m{};
        m.name_index=index(*b,p,scene.strings().size());
        m.frame=next(*b,p);m.kind=next(*b,p);
        if(m.kind>4)throw FormatError("unsupported NAME marker kind");
        if(m.kind>=2)m.related_name_index=index(*b,p,scene.strings().size());
        out.markers_.push_back(m);
    }
    return out;
}
std::vector<std::size_t> TimelineNames::find(const Scene& scene,std::string_view name) const{
    std::vector<std::size_t> result;
    for(std::size_t i=0;i<markers_.size();++i){
        auto idx=markers_[i].name_index;
        if(!idx||idx>scene.strings().size())throw FormatError("NAME lookup with incompatible scene");
        if(scene.strings()[idx-1]==name)result.push_back(i);
    }
    return result;
}
}
