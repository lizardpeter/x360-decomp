#include "formats/xui_catalog.hpp"
#include <algorithm>
namespace x360::formats::xui {
Catalog Catalog::open(std::vector<std::uint8_t> image,std::span<const ResourceDescriptor> resources){
    Catalog out;out.image_=std::move(image);
    std::vector<std::pair<std::size_t,std::size_t>> spans;
    for(auto& r:resources){
        if(r.id.empty()||!r.size||r.offset>out.image_.size()||r.size>out.image_.size()-r.offset)
            throw FormatError("invalid catalog resource extent");
        Bytes b=Bytes(out.image_).subspan(r.offset,r.size);
        if(!out.resources_.emplace(r.id,b).second)throw FormatError("duplicate catalog resource id");
        spans.emplace_back(r.offset,r.offset+r.size);
        if(b.size()>=4&&std::equal(b.begin(),b.begin()+4,"XUIZ"))
            out.archives_.emplace(r.id,Archive::parse(b));
    }
    std::sort(spans.begin(),spans.end());
    for(std::size_t i=1;i<spans.size();++i)
        if(spans[i].first<spans[i-1].second)throw FormatError("overlapping catalog resources");
    return out;
}
std::optional<Bytes> Catalog::resource(std::string_view id) const{
    auto i=resources_.find(id);if(i==resources_.end())return {};return i->second;
}
const Archive* Catalog::archive(std::string_view id) const{
    auto i=archives_.find(id);return i==archives_.end()?nullptr:&i->second;
}
std::optional<Bytes> Catalog::find(std::string_view id,std::string_view member) const{
    auto a=archive(id);return a?a->find(member):std::nullopt;
}
std::optional<Scene> Catalog::scene(std::string_view id,std::string_view member) const{
    auto b=find(id,member);return b?std::optional<Scene>{Scene::parse(*b)}:std::nullopt;
}
std::optional<StringTable> Catalog::strings(std::string_view id,std::string_view member) const{
    auto b=find(id,member);return b?std::optional<StringTable>{StringTable::parse(*b)}:std::nullopt;
}
}
