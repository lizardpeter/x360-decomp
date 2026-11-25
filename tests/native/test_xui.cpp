#include "formats/xui.hpp"
#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>
using namespace x360::formats::xui;
using V=std::vector<std::uint8_t>;
static void check(bool b,const char* why){if(!b){std::cerr<<why<<'\n';std::exit(1);}}
static void append(V& b,std::string_view s){b.insert(b.end(),s.begin(),s.end());}
static void w32(V& b,std::uint32_t x){for(int shift=24;shift>=0;shift-=8)b.push_back(std::uint8_t(x>>shift));}
static void w16(V& b,std::uint16_t x){b.push_back(std::uint8_t(x>>8));b.push_back(std::uint8_t(x));}
static void put32(V& b,std::size_t p,std::uint32_t x){for(int i=0;i<4;++i)b[p+i]=std::uint8_t(x>>(24-i*8));}
template<class F> static void rejects(F f,const char* why){try{f();}catch(const FormatError&){return;}check(false,why);}
static V archive(std::string_view second="same",bool equal=true){
    V b,t;append(b,"XUIZ");w32(b,3);w32(b,0);w32(b,0);
    w32(t,2);w32(t,0);t.push_back(4);append(t,"same");
    w32(t,2);w32(t,2);t.push_back(std::uint8_t(second.size()));append(t,second);
    w32(b,t.size());w16(b,2);b.insert(b.end(),t.begin(),t.end());
    append(b,equal?"ABAB":"ABCD");put32(b,8,b.size());return b;
}
static V scene(){
    V b;append(b,"XUIB");w32(b,8);w32(b,0);w16(b,14);w32(b,0);w16(b,2);
    b.insert(b.end(),{0x07,0x1f,0x07,0});
    append(b,"STRN");w32(b,48);w32(b,13);
    append(b,"DATA");w32(b,61);w32(b,3);
    w32(b,5);w16(b,2);append(b,"A");b.push_back(0);
    // A surrogate pair occupies two UTF-16 units plus NUL, 5 UTF-8 bytes.
    b.insert(b.end(),{0xf0,0x9f,0x98,0x80,0});
    append(b,"XYZ");put32(b,14,b.size());return b;
}
static V strings(unsigned mode){
    V b;append(b,"XUIS");b.push_back(2);b.push_back(mode);w32(b,0);w16(b,mode?2:0);
    if(mode){append(b,"alpha");b.push_back(0);if(mode==1)b.insert(b.end(),{1,10,0,7});
        b.insert(b.end(),{0xc3,0xa9,0});if(mode==1)b.insert(b.end(),{3,0,0,8});}
    put32(b,6,b.size());return b;
}
int main(){
    auto a=archive();auto av=Archive::parse(a);
    check(av.entries().size()==2&&av.find("same")->size()==2,"identical duplicate");
    check(!av.find("SAME"),"exact case lookup");
    auto conflict=archive("same",false);auto cv=Archive::parse(conflict);
    rejects([&]{cv.find("same");},"conflicting duplicate lookup");
    auto rel=archive("..\\handles\\item",false);auto rv=Archive::parse(rel);
    check(rv.find("..\\handles\\item").has_value(),"virtual relative path");
    auto overlap=a;put32(overlap,39,0); // second member offset at 22+13+4
    rejects([&]{Archive::parse(overlap);},"overlapping member accepted");
    auto s=scene();auto sv=Scene::parse(s);
    check(sv.strings().size()==2&&sv.strings()[0]=="A"&&sv.string_units()==5,"UTF-16 length");
    check(sv.section("DATA")->size()==3&&sv.directory_prefix().size()==4,"section lookup");
    auto wrong=s;put32(wrong,48,7);rejects([&]{Scene::parse(wrong);},"wrong string length");
    wrong=s;wrong[56]=0xc0;rejects([&]{Scene::parse(wrong);},"invalid UTF8");
    for(unsigned mode=0;mode<3;++mode){auto x=strings(mode);auto v=StringTable::parse(x);
        check(v.mode()==mode&&v.entries().size()==(mode?2:0),"XUIS mode");
        if(mode==1)check(v.entries()[1].metadata[0]==3&&v.entries()[1].metadata[3]==8,"localization metadata");
        for(std::size_t i=0;i<x.size();++i)rejects([&]{StringTable::parse(Bytes(x).first(i));},"truncated XUIS accepted");
    }
    for(std::size_t i=0;i<a.size();++i)rejects([&]{Archive::parse(Bytes(a).first(i));},"truncated XUIZ accepted");
    for(std::size_t i=0;i<s.size();++i)rejects([&]{Scene::parse(Bytes(s).first(i));},"truncated XUIB accepted");
    std::cout<<"XUI archive, scene, Unicode, localization, duplicate and truncation tests passed\n";
}
