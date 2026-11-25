#include "os/xam/lua_scalar.hpp"
#include <bit>
#include <cmath>
#include <algorithm>
namespace x360::os::xam::lua {
namespace {
using formats::lua51::Prototype;
using formats::lua51::Number;
struct TypeError{};
struct Limit{};
constexpr std::size_t max_string=1024*1024;
bool truth(const Scalar& s){
    if(std::holds_alternative<std::monostate>(s))return false;
    if(auto b=std::get_if<bool>(&s))return *b;
    return true;
}
double number(const Scalar& s){if(auto n=std::get_if<double>(&s))return *n;throw TypeError{};}
const std::string& string(const Scalar& s){if(auto t=std::get_if<std::string>(&s))return *t;throw TypeError{};}
Scalar convert(const formats::lua51::Constant& k){
    if(auto n=std::get_if<Number>(&k))return std::bit_cast<double>(n->bits);
    if(auto b=std::get_if<bool>(&k))return *b;
    if(auto s=std::get_if<std::string>(&k))return *s;
    return std::monostate{};
}
bool less(const Scalar& a,const Scalar& b,bool equal){
    if(auto n=std::get_if<double>(&a)){auto r=number(b);return equal?*n<=r:*n<r;}
    // Binary comparison matches the original subset for the ASCII fixtures;
    // locale-dependent string ordering is outside this runtime.
    if(auto s=std::get_if<std::string>(&a)){auto& t=string(b);return equal?*s<=t:*s<t;}
    throw TypeError{};
}
}
bool eligible(const Prototype& p){
    if(p.upvalues||!p.children.empty()||p.code.empty())return false;
    for(auto w:p.code){
        unsigned op=w&63;
        if(!(op<=3||(op>=12&&op<=27)||op==30||op==31||op==32))return false;
        if(op==30&&!(w>>23))return false;
    }
    return true;
}
Result execute(const Prototype& p,std::span<const Scalar> arguments,std::size_t budget){
    if(!eligible(p))return {ResultCode::unsupported,{},0};
    // Public callers may construct prototypes directly: check bounds and
    // branch targets before indexing register or constant arrays.
    (void)formats::lua51::verify_flow(p);
    std::vector<Scalar> r(p.max_stack),k;
    for(auto& v:p.constants)k.push_back(convert(v));
    const auto n=std::min<std::size_t>(arguments.size(),p.parameters);
    std::copy_n(arguments.begin(),n,r.begin());
    for(auto& s:r)if(auto t=std::get_if<std::string>(&s);t&&t->size()>max_string)return {ResultCode::budget_exhausted,{},0};
    for(auto& s:k)if(auto t=std::get_if<std::string>(&s);t&&t->size()>max_string)return {ResultCode::budget_exhausted,{},0};
    std::size_t pc=0,steps=0;
    auto rk=[&](unsigned x)->const Scalar&{return x&256?k[x&255]:r[x];};
    try{
        while(steps<budget){
            ++steps;auto w=p.code[pc++];
            unsigned op=w&63,a=(w>>6)&255,c=(w>>14)&511,b=w>>23,bx=w>>14;
            auto jump=[&](){pc=static_cast<std::size_t>(static_cast<std::int64_t>(pc)+static_cast<std::int64_t>(bx)-131071);};
            switch(op){
                case 0:r[a]=r[b];break;
                case 1:r[a]=k[bx];break;
                case 2:r[a]=bool(b);pc+=bool(c);break;
                case 3:for(auto i=a;i<=b;++i)r[i]=std::monostate{};break;
                case 12:case 13:case 14:case 15:case 16:case 17:{
                    auto x=number(rk(b)),y=number(rk(c));double z{};
                    switch(op){
                        case 12:z=x+y;break;case 13:z=x-y;break;case 14:z=x*y;break;
                        case 15:z=x/y;break;case 16:z=x-std::floor(x/y)*y;break;case 17:z=std::pow(x,y);break;
                    }r[a]=z;break;
                }
                case 18:r[a]=-number(r[b]);break;
                case 19:r[a]=!truth(r[b]);break;
                case 20:r[a]=double(string(r[b]).size());break;
                case 21:{
                    std::string result;
                    for(auto i=b;i<=c;++i){auto& s=string(r[i]);if(s.size()>max_string-result.size())throw Limit{};result+=s;}
                    r[a]=std::move(result);break;
                }
                case 22:jump();break;
                case 23:case 24:case 25:{
                    bool result=op==23?rk(b)==rk(c):less(rk(b),rk(c),op==25);
                    if(result!=bool(a))++pc;break;
                }
                case 26:if(truth(r[a])!=bool(c))++pc;break;
                case 27:if(truth(r[b])==bool(c))r[a]=r[b];else ++pc;break;
                case 30:return {ResultCode::returned,{r.begin()+a,r.begin()+a+b-1},steps};
                case 31:{
                    auto step=number(r[a+2]),v=number(r[a])+step,limit=number(r[a+1]);r[a]=v;
                    if(step>0?v<=limit:v>=limit){r[a+3]=v;jump();}break;
                }
                case 32:r[a]=number(r[a])-number(r[a+2]);jump();break;
                default:return {ResultCode::unsupported,{},steps};
            }
        }
    }catch(const TypeError&){return {ResultCode::type_error,{},steps};}
     catch(const Limit&){return {ResultCode::budget_exhausted,{},steps};}
    return {ResultCode::budget_exhausted,{},steps};
}
}
