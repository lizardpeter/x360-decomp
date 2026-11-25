#include "os/xam/lua_scalar.hpp"
#include <bit>
#include <cstdlib>
#include <iostream>
using namespace x360::os::xam::lua;
using x360::formats::lua51::Prototype;
using x360::formats::lua51::Number;
static void check(bool b,const char* s){if(!b){std::cerr<<s<<'\n';std::exit(1);}}
static std::uint32_t abc(unsigned op,unsigned a,unsigned b,unsigned c){return op|(a<<6)|(c<<14)|(b<<23);}
static std::uint32_t abx(unsigned op,unsigned a,unsigned bx){return op|(a<<6)|(bx<<14);}
int main(){
    Prototype p;p.max_stack=4;p.parameters=2;
    p.code={abc(12,2,0,1),abc(14,2,2,1),abc(30,2,2,0)};
    std::array<Scalar,2> a{3.,4.};
    auto x=execute(p,a);check(x.code==ResultCode::returned&&x.values==std::vector<Scalar>{28.},"arithmetic");
    a[0]=std::string("3");check(execute(p,a).code==ResultCode::type_error,"no implicit coercion");
    p.code={abc(21,2,0,1),abc(30,2,2,0)};
    a={std::string("a\0",2),std::string("b")};x=execute(p,a);
    check(x.values==std::vector<Scalar>{std::string("a\0b",3)},"binary concat");
    p.code={abc(19,2,0,0),abc(30,2,2,0)};
    a[0]=0.;check(execute(p,a).values==std::vector<Scalar>{false},"zero is truthy");
    a[0]=std::monostate{};check(execute(p,a).values==std::vector<Scalar>{true},"nil is false");
    p.constants={Number{std::bit_cast<std::uint64_t>(2.)}};
    p.code={abc(23,1,0,256),abx(22,0,131072),abc(2,2,0,1),abc(2,2,1,0),abc(30,2,2,0)};
    // Explicit paired JMP and skip behavior; use a simpler branch below.
    p.code={abc(23,1,0,256),abx(22,0,131073),abc(2,2,0,0),abc(30,2,2,0),abc(2,2,1,0),abc(30,2,2,0)};
    a[0]=2.;check(execute(p,a).values==std::vector<Scalar>{true},"equal branch");
    a[0]=true;check(execute(p,a).values==std::vector<Scalar>{false},"different types not equal");
    p.code={abx(22,0,131070)};check(execute(p,a,17).code==ResultCode::budget_exhausted,"bounded loop");
    p.code={abc(5,0,0,0),abc(30,0,2,0)};check(!eligible(p)&&execute(p,a).code==ResultCode::unsupported,"host globals excluded");
    std::cout<<"Scalar execution arithmetic, binary strings, branching, truth and budget tests passed\n";
}
