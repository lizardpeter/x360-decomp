#include "formats/xui_structure.hpp"
#include "formats/xui_timeline.hpp"
namespace x360::formats::xui {
namespace {
std::uint32_t next(Bytes b,std::size_t& p){
    if(p>=b.size())throw FormatError("truncated scene compact integer");
    std::uint32_t x=b[p++];
    if(x==255){
        if(b.size()-p<4)throw FormatError("truncated scene 32-bit integer");
        x=0;for(unsigned i=0;i<4;++i)x=(x<<8)|b[p++];
        if(x<3840)throw FormatError("noncanonical scene 32-bit integer");
    }else if(x>=240){
        if(p>=b.size())throw FormatError("truncated scene extended integer");
        x=((x&15)<<8)|b[p++];
        if(x<240)throw FormatError("noncanonical scene extended integer");
    }
    return x;
}
}
std::optional<SceneStructure> SceneStructure::parse(const Scene& scene){
    if(scene.version()==5)return std::nullopt;
    if(scene.version()!=8)throw FormatError("unsupported scene structure version");
    SceneStructure s;auto prefix=scene.directory_prefix();std::size_t p=0;
    for(auto& value:s.header)value=next(prefix,p);
    if(p!=prefix.size())throw FormatError("unexpected scene prefix fields");
    if(auto keys=scene.section("KEYP")){
        p=0;
        if(s.key_token_count()>keys->size())throw FormatError("impossible KEYP count");
        s.key_tokens.reserve(s.key_token_count());
        while(p<keys->size())s.key_tokens.push_back(next(*keys,p));
    }
    if(s.key_token_count()!=s.key_tokens.size())throw FormatError("KEYP count disagrees with scene header");
    if(s.name_record_count()!=TimelineNames::parse(scene).markers().size())throw FormatError("NAME count disagrees with scene header");
    auto data=scene.section("DATA");
    if(!data)throw FormatError("missing scene DATA");
    p=0;s.root_class_index=next(*data,p);
    if(!s.root_class_index||s.root_class_index>scene.strings().size())throw FormatError("root class index out of bounds");
    if(scene.strings()[s.root_class_index-1]!="XuiCanvas")throw FormatError("unsupported root class");
    s.remaining_data=data->subspan(p);
    return s;
}
}
