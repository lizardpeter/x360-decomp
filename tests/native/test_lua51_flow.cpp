#include "formats/lua51_flow.hpp"
#include <cstdlib>
#include <iostream>
using namespace x360::formats::lua51;
using x360::formats::xui::FormatError;
static void check(bool b,const char* why){if(!b){std::cerr<<why<<'\n';std::exit(1);}}
static std::uint32_t abc(unsigned op,unsigned a,unsigned b,unsigned c){return op|(a<<6)|(c<<14)|(b<<23);}
static std::uint32_t abx(unsigned op,unsigned a,unsigned bx){return op|(a<<6)|(bx<<14);}
static std::uint32_t jump(int d){return abx(22,0,static_cast<unsigned>(131071+d));}
template<class F>static void rejects(F f){try{f();}catch(const FormatError&){return;}check(false,"invalid flow accepted");}
int main(){
    Prototype p;p.max_stack=4;p.upvalues=1;p.constants.emplace_back(std::string("test"));
    Prototype child;child.max_stack=2;child.upvalues=2;child.code={abc(30,0,1,0)};p.children.push_back(child);
    p.code={abx(36,0,0),abc(0,0,1,0),abc(4,0,0,0),abc(26,0,0,1),jump(1),abc(30,0,1,0),abc(30,0,1,0)};
    auto f=verify_flow(p);
    check(f.instructions.size()==5&&f.capture_words==2&&f.reachable==5,"capture flow");
    check(f.instructions[0].successors==std::vector<std::uint32_t>{3},"capture skip");
    check(f.instructions[1].successors==std::vector<std::uint32_t>{4,5},"conditional");
    auto c=verify_flow(Chunk{p});check(c.prototypes==2&&c.instructions==6&&c.edges==4,"recursive census");
    auto b=p;b.code[4]=jump(-4);rejects([&]{verify_flow(b);}); // targets capture word
    b=p;b.code[1]=abc(0,0,4,0);rejects([&]{verify_flow(b);});
    b=p;b.code[2]=abc(4,0,1,0);rejects([&]{verify_flow(b);});
    b=p;b.code[4]=jump(100);rejects([&]{verify_flow(b);});
    b=p;b.code[4]=abc(0,0,1,0);rejects([&]{verify_flow(b);});
    b=p;b.code[0]=abx(36,0,1);rejects([&]{verify_flow(b);});
    b=p;b.code={abc(34,0,1,0),0xffffffff,abc(30,0,1,0)};
    f=verify_flow(b);check(f.instructions.size()==2&&f.extra_words==1,"SETLIST");
    b.code={abc(30,0,1,0),abc(30,0,1,0)};f=verify_flow(b);check(f.reachable==1,"unreachable code");
    b.code={abx(5,0,0),abc(30,0,1,0)};b.constants[0]=true;rejects([&]{verify_flow(b);});
    std::cout<<"Lua flow, operand bounds, closure capture and invalid branch tests passed\n";
}
