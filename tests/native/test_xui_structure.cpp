#include "formats/xui_structure.hpp"
#include <cstdlib>
#include <iostream>
using namespace x360::formats::xui;
using V=std::vector<std::uint8_t>;
static void check(bool b,const char* why){if(!b){std::cerr<<why<<'\n';std::exit(1);}}
static void w32(V& b,std::uint32_t x){for(int i=24;i>=0;i-=8)b.push_back(std::uint8_t(x>>i));}
static void tag(V& b,std::string_view s){b.insert(b.end(),s.begin(),s.end());}
static V make(V prefix,V keys,V data){
    V str;w32(str,10);str.insert(str.end(),{0,1});tag(str,"XuiCanvas");str.push_back(0);
    V names{1,0,0};
    std::vector<std::pair<std::string,V>> sections{{"STRN",str},{"KEYP",keys},{"NAME",names},{"DATA",data}};
    V b;tag(b,"XUIB");w32(b,8);w32(b,0);b.insert(b.end(),{0,14});w32(b,0);b.insert(b.end(),{0,4});
    b.insert(b.end(),prefix.begin(),prefix.end());std::uint32_t pos=b.size()+48;
    for(auto& [name,bytes]:sections){tag(b,name);w32(b,pos);w32(b,bytes.size());pos+=bytes.size();}
    for(auto& [name,bytes]:sections)b.insert(b.end(),bytes.begin(),bytes.end());
    for(int i=0;i<4;++i)b[14+i]=std::uint8_t(pos>>(24-i*8));return b;
}
template<class F>static void rejects(F f){try{f();}catch(const FormatError&){return;}check(false,"malformed scene accepted");}
int main(){
    V prefix{1,255,0,0,0x20,0xdf,1,0,0,0,0,0,2,0,1,1};
    auto bytes=make(prefix,{3,0xf1,0x2c},{1,0xaa,0xbb});
    auto scene=Scene::parse(bytes);auto s=SceneStructure::parse(scene);
    check(s&&s->header[1]==8415&&s->key_tokens==std::vector<std::uint32_t>{3,300},"header / KEYP");
    check(s->root_class_index==1&&s->remaining_data.size()==2&&s->remaining_data[0]==0xaa,"DATA root");
    auto bad=[&](V p,V k,V d){auto b=make(p,k,d);auto sc=Scene::parse(b);rejects([&]{SceneStructure::parse(sc);});};
    bad(prefix,{3},{1});bad(prefix,{3,0xf1},{1});bad(prefix,{3,0xf0,1},{1});
    bad(prefix,{3,0xf1,0x2c},{2});bad(prefix,{3,0xf1,0x2c},{});
    auto wrong=prefix;wrong[14]=2;bad(wrong,{3,0xf1,0x2c},{1});
    wrong=prefix;wrong.push_back(0);bad(wrong,{3,0xf1,0x2c},{1});
    std::cout<<"Modern scene prefix, 32-bit escape, KEYP/NAME census and DATA root checks passed\n";
}
