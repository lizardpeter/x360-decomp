#include "formats/xui_values.hpp"
#include "formats/xui_catalog.hpp"
#include "os/xam/xui/geometry.hpp"
#include <bit>
#include <cmath>
#include <cstdlib>
#include <iostream>
#include <string_view>
#include <vector>
using namespace x360::formats::xui;
using V=std::vector<std::uint8_t>;
static void check(bool b,const char* m){if(!b){std::cerr<<m<<'\n';std::exit(1);}}
static void tag(V& b,std::string_view s){b.insert(b.end(),s.begin(),s.end());}
static void w32(V& b,std::uint32_t x){for(int shift=24;shift>=0;shift-=8)b.push_back(std::uint8_t(x>>shift));}
static void w16(V& b,std::uint16_t x){b.push_back(std::uint8_t(x>>8));b.push_back(std::uint8_t(x));}
static void f32(V& b,float x){w32(b,std::bit_cast<std::uint32_t>(x));}
static void put32(V& b,std::size_t p,std::uint32_t x){for(int i=0;i<4;++i)b[p+i]=std::uint8_t(x>>(24-i*8));}
template<class F> static void rejects(F f,const char* m){try{f();}catch(const std::exception&){return;}check(false,m);}
static V make_scene(bool bad=false){
    std::vector<std::pair<std::string_view,V>> tables;
    V s;w32(s,2);w16(s,1);tag(s,"A");s.push_back(0);tables.push_back({"STRN",s});
    V f;f32(f,1.5f);f32(f,-2.25f);tables.push_back({"FLOT",f});
    V v;for(float x:{10.f,20.f,0.f})f32(v,x);tables.push_back({"VECT",v});
    V q;for(float x:{0.f,0.f,0.f,1.f})f32(q,x);tables.push_back({"QUAT",q});
    V c;w32(c,0x80ff0080);tables.push_back({"COLR",c});
    V p;w32(p,108);f32(p,10);f32(p,20);w32(p,bad?5:4);
    for(float x:{0.f,0.f,0.f,0.f,10.f,0.f,10.f,0.f,10.f,0.f,10.f,20.f,
        10.f,20.f,10.f,20.f,0.f,20.f,0.f,20.f,0.f,20.f,0.f,0.f})f32(p,x);
    tables.push_back({"CUST",p});
    V b;tag(b,"XUIB");w32(b,8);w32(b,0);w16(b,14);w32(b,0);w16(b,tables.size());
    b.insert(b.end(),{1,2,3,4});
    std::uint32_t pos=b.size()+tables.size()*12;
    for(auto& [name,data]:tables){tag(b,name);w32(b,pos);w32(b,data.size());pos+=data.size();}
    for(auto& [name,data]:tables)b.insert(b.end(),data.begin(),data.end());
    put32(b,14,b.size());return b;
}
static V wrap(const V& scene){
    V b;tag(b,"XUIZ");w32(b,3);w32(b,0);w32(b,0);w32(b,18);w16(b,1);
    w32(b,scene.size());w32(b,0);b.push_back(9);tag(b,"shape.xur");
    b.insert(b.end(),scene.begin(),scene.end());put32(b,8,b.size());return b;
}
int main(){
    auto raw=make_scene();auto s=Scene::parse(raw);auto v=SceneValues::parse(s);
    check(v.floats==std::vector<float>{1.5f,-2.25f},"FLOT");
    check(v.vectors==std::vector<Vec3>{{10,20,0}},"VECT");
    check(v.quaternions==std::vector<Quaternion>{{0,0,0,1}},"QUAT");
    check(v.colors==std::vector<std::uint32_t>{0x80ff0080},"COLR");
    check(v.custom.size()==1&&v.custom[0].segments.size()==4,"CUST");
    using x360::os::xam::xui::flatten_closed_shape;
    auto path=flatten_closed_shape(v.custom[0]);
    check(path==std::vector<Vec2>{{0,0},{10,0},{10,20},{0,20},{0,0}},"rectangle contour");
    auto curve=v.custom[0];curve.segments[0].control1={0,-10};curve.segments[0].control2={10,-10};
    auto fine=flatten_closed_shape(curve,0.05f),coarse=flatten_closed_shape(curve,1.f);
    check(fine.size()>coarse.size()&&fine.front()==fine.back(),"curve subdivision");
    rejects([&]{flatten_closed_shape(curve,0.01f,0);},"tolerance failure");
    rejects([&]{flatten_closed_shape(curve,0.f);},"invalid tolerance");
    auto invalid=make_scene(true);auto scene=Scene::parse(invalid);
    rejects([&]{SceneValues::parse(scene);},"invalid CUST count");
    auto archive=wrap(raw);auto n=archive.size();
    std::array<ResourceDescriptor,1> desc{{{"bundle",0,n}}};
    auto catalog=Catalog::open(std::move(archive),desc);
    check(catalog.resource_count()==1&&catalog.archive_count()==1,"catalog count");
    auto moved=std::move(catalog);
    check(moved.scene("bundle","shape.xur")->strings()[0]=="A","move preserved owned resource");
    check(!moved.find("missing","shape.xur")&&!moved.find("bundle","missing"),"missing resource");
    std::array<ResourceDescriptor,2> bad{{{"a",0,n},{"b",0,n}}};
    rejects([&]{Catalog::open(wrap(raw),bad);},"overlapping resources");
    std::cout<<"XUI typed tables, closed cubic paths and owned resource catalog passed\n";
}
