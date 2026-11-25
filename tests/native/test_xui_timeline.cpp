#include "formats/xui_timeline.hpp"
#include <cstdlib>
#include <iostream>
using namespace x360::formats::xui;
using V=std::vector<std::uint8_t>;
static void check(bool b,const char* m){if(!b){std::cerr<<m<<'\n';std::exit(1);}}
static void append(V& b,std::string_view s){b.insert(b.end(),s.begin(),s.end());}
static void w32(V& b,std::uint32_t x){for(int i=24;i>=0;i-=8)b.push_back(std::uint8_t(x>>i));}
static V scene(V names){
    V b;append(b,"XUIB");w32(b,8);w32(b,0);b.insert(b.end(),{0,14});w32(b,52+names.size());
    b.insert(b.end(),{0,2});append(b,"STRN");w32(b,44);w32(b,8);
    append(b,"NAME");w32(b,52);w32(b,names.size());w32(b,2);b.insert(b.end(),{0,1,'A',0});
    b.insert(b.end(),names.begin(),names.end());return b;
}
template<class F>static void rejects(F f){try{f();}catch(const FormatError&){return;}check(false,"malformed NAME accepted");}
int main(){
    auto bytes=scene({1,0,0,1,0xf1,0x2c,3,1,1,0xef,1});
    auto s=Scene::parse(bytes);auto t=TimelineNames::parse(s);
    check(t.markers().size()==3,"marker count");
    check(t.markers()[1].frame==300&&t.markers()[1].related_name_index==1,"extended integer");
    check(t.find(s,"A")==std::vector<std::size_t>{0,1,2},"duplicates");
    check(t.find(s,"B").empty(),"missing name");
    for(auto bad:{V{0,0,0},V{2,0,0},V{1,0,5},V{1,0,3},V{1,0xf1},V{1,0xf0,1,0},V{1,0,4,2}}){
        auto raw=scene(bad);auto invalid=Scene::parse(raw);rejects([&]{TimelineNames::parse(invalid);});
    }
    std::cout<<"NAME compact integers, references, repeated labels and invalid records passed\n";
}
