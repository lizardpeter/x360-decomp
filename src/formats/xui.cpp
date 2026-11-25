#include "formats/xui.hpp"
#include <algorithm>
#include <limits>
#include <set>
#include <utility>

namespace x360::formats::xui {
namespace {
[[noreturn]] void fail(const char* why){throw FormatError(why);}
Bytes part(Bytes b,std::size_t off,std::size_t n){
    if(off>b.size()||n>b.size()-off)fail("truncated XUI range");
    return b.subspan(off,n);
}
std::uint32_t be32(Bytes b,std::size_t p){
    auto v=part(b,p,4);
    return (std::uint32_t(v[0])<<24)|(std::uint32_t(v[1])<<16)|(std::uint32_t(v[2])<<8)|v[3];
}
std::uint16_t be16(Bytes b,std::size_t p){
    auto v=part(b,p,2);return std::uint16_t((std::uint16_t(v[0])<<8)|v[1]);
}
std::uint8_t u8(Bytes b,std::size_t p){return part(b,p,1)[0];}
std::string_view string(Bytes b){
    return {reinterpret_cast<const char*>(b.data()),b.size()};
}
bool magic(Bytes b,std::string_view tag){
    return b.size()>=tag.size()&&string(b.first(tag.size()))==tag;
}
std::size_t utf16_units(Bytes b){
    std::size_t count=0;
    for(std::size_t i=0;i<b.size();){
        auto c=b[i++];std::uint32_t cp=c,min=0;unsigned more=0;
        if(c<0x80){}
        else if((c&0xe0)==0xc0){cp=c&31;more=1;min=0x80;}
        else if((c&0xf0)==0xe0){cp=c&15;more=2;min=0x800;}
        else if((c&0xf8)==0xf0){cp=c&7;more=3;min=0x10000;}
        else fail("invalid UTF-8 lead");
        if(more>b.size()-i)fail("truncated UTF-8");
        for(unsigned j=0;j<more;++j){auto t=b[i++];if((t&0xc0)!=0x80)fail("invalid UTF-8 continuation");cp=(cp<<6)|(t&63);}
        if(cp<min||cp>0x10ffff||(cp>=0xd800&&cp<=0xdfff))fail("invalid Unicode scalar");
        count+=cp>0xffff?2:1;
    }
    return count;
}
std::string_view cstring(Bytes b,std::size_t& p){
    if(p>=b.size())fail("missing XUI string");
    auto tail=b.subspan(p);auto end=std::find(tail.begin(),tail.end(),std::uint8_t{0});
    if(end==tail.end())fail("unterminated XUI string");
    auto n=static_cast<std::size_t>(end-tail.begin());
    auto value=tail.first(n);utf16_units(value);p+=n+1;return string(value);
}
bool valid_tag(Bytes bytes){
    return bytes.size()==4&&std::all_of(bytes.begin(),bytes.end(),[](auto c){return c>='A'&&c<='Z';});
}
bool directory_at(Bytes input,std::size_t p,std::size_t count){
    if(p>input.size()||count>(input.size()-p)/12)return false;
    std::size_t next=p+count*12;
    std::set<std::string_view> tags;
    for(std::size_t i=0;i<count;++i){
        auto r=p+i*12;auto tag=input.subspan(r,4);
        if(!valid_tag(tag)||!tags.insert(string(tag)).second)return false;
        auto off=be32(input,r+4),n=be32(input,r+8);
        if(off!=next||n>input.size()-next)return false;
        next+=n;
    }
    return next==input.size();
}
}
Archive Archive::parse(Bytes b){
    if(b.size()<22||!magic(b,"XUIZ")||be32(b,4)!=3||be32(b,8)!=b.size()||be32(b,12)!=0)
        fail("unsupported XUIZ header");
    auto table_size=be32(b,16);auto count=be16(b,20);
    auto table=part(b,22,table_size);auto payload=b.subspan(22+std::size_t(table_size));
    if(count>table.size()/9)fail("impossible XUIZ member count");
    Archive a;std::size_t p=0;a.entries_.reserve(count);
    for(unsigned i=0;i<count;++i){
        auto n=be32(table,p),off=be32(table,p+4);auto length=u8(table,p+8);p+=9;
        if(!length)fail("empty XUIZ member name");
        auto raw=part(table,p,length);p+=length;
        utf16_units(raw);
        if(std::find(raw.begin(),raw.end(),std::uint8_t{0})!=raw.end())fail("NUL in XUIZ member name");
        // The original archives include ../handles virtual names. Do not
        // normalize them into filesystem paths, and never write member data.
        a.entries_.push_back({string(raw),off,part(payload,off,n)});
    }
    if(p!=table.size())fail("XUIZ directory size mismatch");
    std::vector<const ArchiveEntry*> sorted;
    for(auto& e:a.entries_)sorted.push_back(&e);
    std::sort(sorted.begin(),sorted.end(),[](auto a,auto b){return a->offset<b->offset;});
    std::size_t end=0;
    for(auto e:sorted){
        if(e->offset!=end)fail("noncontiguous or overlapping XUIZ payload");
        end+=e->data.size();
    }
    if(end!=payload.size())fail("unreferenced XUIZ payload");
    return a;
}
std::optional<Bytes> Archive::find(std::string_view name) const{
    std::optional<Bytes> result;
    for(auto& e:entries_){
        if(e.name!=name)continue;
        if(result&&!std::equal(result->begin(),result->end(),e.data.begin(),e.data.end()))
            fail("ambiguous XUIZ member");
        if(!result)result=e.data;
    }
    return result;
}
Scene Scene::parse(Bytes b){
    if(b.size()<20||!magic(b,"XUIB")||be32(b,4)!=8||be32(b,8)!=0||be16(b,12)!=14||be32(b,14)!=b.size())
        fail("unsupported XUIB header");
    std::size_t count=be16(b,18);
    if(!count||count>64||count>(b.size()-20)/12)fail("invalid XUIB section count");
    // The variable prefix has not been semantically reconstructed. The
    // observed directory begins with STRN and is uniquely identified by
    // its exact, contiguous section extents. No arbitrary magic-only match.
    std::optional<std::size_t> directory;
    auto last=std::min<std::size_t>(512,b.size()-count*12);
    for(std::size_t p=20;p<=last;++p){
        if(!magic(b.subspan(p),"STRN")||!directory_at(b,p,count))continue;
        if(directory)fail("ambiguous XUIB directory");
        directory=p;
    }
    if(!directory)fail("XUIB section directory not found");
    Scene s;s.prefix_=b.subspan(20,*directory-20);s.sections_.reserve(count);
    for(std::size_t i=0;i<count;++i){
        auto p=*directory+i*12;Section section{};
        std::copy_n(b.begin()+p,4,section.tag.begin());
        section.data=part(b,be32(b,p+4),be32(b,p+8));
        s.sections_.push_back(section);
    }
    auto str=s.sections_.front().data;
    s.units_=be32(str,0);auto n=be16(str,4);std::size_t p=6;
    if(n>str.size()-6)fail("invalid STRN count");
    s.strings_.reserve(n);
    for(unsigned i=0;i<n;++i)s.strings_.push_back(cstring(str,p));
    if(p!=str.size())fail("STRN trailing data");
    // This is UTF-16 code-unit count, including NULs, not UTF-8 byte count.
    // The difference is observable in two original multilingual scenes.
    if(utf16_units(str.subspan(6))!=s.units_)fail("STRN UTF-16 length mismatch");
    return s;
}
std::optional<Bytes> Scene::section(std::string_view tag) const noexcept{
    for(auto& s:sections_)if(s.name()==tag)return s.data;
    return {};
}
StringTable StringTable::parse(Bytes b){
    if(b.size()<12||!magic(b,"XUIS")||u8(b,4)!=2||be32(b,6)!=b.size())fail("unsupported XUIS header");
    StringTable t;t.mode_=u8(b,5);auto n=be16(b,10);
    if(t.mode_>2||(t.mode_==0&&n)||n>(b.size()-12)/(t.mode_==1?5:1))fail("unsupported XUIS mode/count");
    std::size_t p=12;t.entries_.reserve(n);
    for(unsigned i=0;i<n;++i){
        LocalizedString entry{};entry.text=cstring(b,p);
        if(t.mode_==1){auto raw=part(b,p,4);std::copy(raw.begin(),raw.end(),entry.metadata.begin());p+=4;}
        t.entries_.push_back(entry);
    }
    if(p!=b.size())fail("XUIS trailing bytes");
    return t;
}
}
