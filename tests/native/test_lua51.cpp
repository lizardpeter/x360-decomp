#include "formats/lua51.hpp"
#include <cstdlib>
#include <iostream>
using namespace x360::formats::lua51;
using x360::formats::xui::FormatError;
using V=std::vector<std::uint8_t>;
static void check(bool b,const char* why){if(!b){std::cerr<<why<<'\n';std::exit(1);}}
static void w32(V& b,std::uint32_t x){for(int i=24;i>=0;i-=8)b.push_back(std::uint8_t(x>>i));}
static void str(V& b,std::string_view s){w32(b,s.size()+1);b.insert(b.end(),s.begin(),s.end());b.push_back(0);}
static V sample(){
    V b{0x1b,'L','u','a',0x51,0,0,4,4,4,8,0};
    str(b,"@synthetic");w32(b,0);w32(b,0);b.insert(b.end(),{0,0,2,4});
    w32(b,3);w32(b,34);w32(b,0xffffffff);w32(b,30);
    w32(b,4);b.insert(b.end(),{0,1,1,3,0x80,0,0,0,0,0,0,0,4});str(b,std::string_view("a\0b",3));
    w32(b,0);w32(b,3);w32(b,1);w32(b,1);w32(b,2);w32(b,1);str(b,"local");w32(b,0);w32(b,3);w32(b,0);
    return b;
}
template<class F>static void rejects(F f){try{f();}catch(const FormatError&){return;}check(false,"malformed Lua accepted");}
int main(){
    auto raw=sample();auto c=Chunk::parse(raw);auto n=census(c);
    check(n.prototypes==1&&n.words==3&&n.setlist_extra==1&&n.opcodes[34]==1&&n.opcodes[30]==1,"SETLIST data classification");
    check(n.constants==4&&n.strings==3&&n.locals==1&&n.lines==3,"debug/constant counts");
    check(std::get<Number>(c.main.constants[2]).bits==0x8000000000000000ull,"negative zero bits");
    check(std::get<std::string>(c.main.constants[3])==std::string("a\0b",3),"embedded NUL");
    for(std::size_t i=0;i<raw.size();++i)rejects([&]{Chunk::parse(Bytes(raw).first(i));});
    auto bad=raw;bad[6]=1;rejects([&]{Chunk::parse(bad);});
    bad=raw;bad.push_back(0);rejects([&]{Chunk::parse(bad);});
    std::cout<<"Lua ABI, constant bits, binary strings, SETLIST and truncation tests passed\n";
}
