#include "formats/png.hpp"
#include <zlib.h>
#include <array>
#include <cstdlib>
#include <iostream>
using namespace x360::formats;
using V=std::vector<std::uint8_t>;
static void check(bool b,const char* why){if(!b){std::cerr<<why<<'\n';std::exit(1);}}
static void word(V& b,std::uint32_t n){for(int i=24;i>=0;i-=8)b.push_back(std::uint8_t(n>>i));}
static void chunk(V& b,std::string_view tag,V payload){
    word(b,payload.size());auto start=b.size();b.insert(b.end(),tag.begin(),tag.end());b.insert(b.end(),payload.begin(),payload.end());
    auto crc=crc32(0,b.data()+start,b.size()-start);word(b,crc);
}
static V make(unsigned w,unsigned h,unsigned depth,unsigned color,V raw,V palette={},V alpha={}){
    V b{137,80,78,71,13,10,26,10};V ihdr;word(ihdr,w);word(ihdr,h);
    ihdr.insert(ihdr.end(),{std::uint8_t(depth),std::uint8_t(color),0,0,0});chunk(b,"IHDR",ihdr);
    if(!palette.empty())chunk(b,"PLTE",palette);
    if(!alpha.empty())chunk(b,"tRNS",alpha);
    uLongf n=compressBound(raw.size());V deflated(n);
    check(compress2(deflated.data(),&n,raw.data(),raw.size(),9)==Z_OK,"test compression");
    deflated.resize(n);chunk(b,"IDAT",deflated);chunk(b,"IEND",{});return b;
}
template<class F>static void rejects(F f){try{f();}catch(const xui::FormatError&){return;}check(false,"invalid PNG accepted");}
int main(){
    auto rgba=make(2,2,8,6,{1,1,2,3,4,4,4,4,4,2,1,1,1,1,2,2,2,2});
    auto im=png::decode(rgba);
    check(im.width==2&&im.height==2&&im.rgba==V{1,2,3,4,5,6,7,8,2,3,4,5,7,8,9,10},"RGBA filters");
    auto indexed=make(3,1,1,3,{0,0xa0},{255,0,0,0,255,0},{12});
    check(png::decode(indexed).rgba==V{0,255,0,255,255,0,0,12,0,255,0,255},"packed indexed alpha");
    check(png::decode(make(1,1,8,4,{0,17,28})).rgba==V{17,17,17,28},"gray alpha");
    for(std::size_t i=0;i<rgba.size();++i)rejects([&]{png::decode(xui::Bytes(rgba).first(i));});
    auto bad=rgba;bad[20]^=1;rejects([&]{png::decode(bad);});
    rejects([&]{png::decode(make(1,1,8,6,{5,0,0,0,0}));});
    rejects([&]{png::decode(make(1,1,8,6,{0,0,0,0,0,1}));});
    rejects([&]{png::decode(make(1,1,8,3,{0,2},{0,0,0}));});
    std::cout<<"PNG RGBA, filters, packed palette, alpha, CRC and truncation passed\n";
}
