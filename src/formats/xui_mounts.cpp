#include "formats/xui_mounts.hpp"
#include <algorithm>
namespace x360::formats::xui {
namespace {
std::string fold(std::string_view key){
    std::string out;out.reserve(key.size());
    for(char c:key){if(c>='A'&&c<='Z')c=char(c-'A'+'a');out.push_back(c=='\\'?'/':c);}
    return out;
}
bool same(Bytes a,Bytes b){return a.size()==b.size()&&std::equal(a.begin(),a.end(),b.begin());}
}
void Mounts::mount(std::string scheme,const Archive& archive){
    if(scheme.empty()||!std::all_of(scheme.begin(),scheme.end(),[](char c){return c>='a'&&c<='z';}))
        throw FormatError("invalid mount scheme");
    // Host file/network providers are intentionally excluded.
    if(scheme=="file"||scheme=="http"||scheme=="https"||scheme=="ftp")
        throw FormatError("external scheme forbidden");
    if(!mounts_.emplace(std::move(scheme),&archive).second)throw FormatError("duplicate mount");
}
ResolvedResource Mounts::resolve(std::string_view uri) const{
    auto delimiter=uri.find("://");
    if(delimiter==std::string_view::npos||delimiter==0)return {ResolveState::malformed,{}};
    auto it=mounts_.find(uri.substr(0,delimiter));
    if(it==mounts_.end())return {ResolveState::unsupported_scheme,{}};
    auto path=uri.substr(delimiter+3);
    if(path.empty()||path.find('\0')!=std::string_view::npos)return {ResolveState::malformed,{}};
    auto key=fold(path);
    const ArchiveEntry* match=nullptr;
    bool exact=false;
    for(auto& e:it->second->entries()){
        if(fold(e.name)!=key)continue;
        // An identical duplicate is harmless, but conflicting case or slash
        // variants cannot be disambiguated by a guessed priority rule.
        if(match&&!same(match->data,e.data))return {ResolveState::ambiguous,{}};
        match=&e;exact|=e.name==path;
    }
    if(!match)return {ResolveState::missing,{}};
    return {exact?ResolveState::exact:ResolveState::normalized,match->data};
}
}
