#include "os/xam/lua_vm.hpp"
#include <algorithm>
#include <bit>
#include <charconv>
#include <cmath>
#include <limits>
#include <map>
#include <type_traits>
#include <utility>
namespace x360::os::xam::lua {
namespace {
using formats::lua51::Prototype;
using Values=std::vector<Value>;
using Cell=std::shared_ptr<Value>;
struct Failure {VmCode code;const char* text;};
[[noreturn]] void fail(VmCode c,const char* text){throw Failure{c,text};}
void require(bool condition,VmCode c,const char* text){if(!condition)fail(c,text);}
bool nil(const Value& v){return std::holds_alternative<std::monostate>(v);}
bool truth(const Value& v){return !nil(v)&&(!std::holds_alternative<bool>(v)||std::get<bool>(v));}
bool valid_key(const Value& v){auto n=std::get_if<double>(&v);return !nil(v)&&(!n||!std::isnan(*n));}
struct Less {
    bool operator()(const Value& a,const Value& b) const {
        if(a.index()!=b.index())return a.index()<b.index();
        return std::visit([](const auto& x,const auto& y){
            using X=std::decay_t<decltype(x)>;using Y=std::decay_t<decltype(y)>;
            if constexpr(std::is_same_v<X,Y>&&!std::is_same_v<X,std::monostate>)return x<y;
            else return false;
        },a,b);
    }
};
struct Table {std::map<Value,Value,Less> entries;};
struct Closure {
    std::shared_ptr<const Prototype> owner;
    const Prototype* p{};
    std::vector<Cell> upvalues;
};
enum Builtin:std::uint8_t{type_fn,tonumber_fn,tostring_fn,next_fn,pairs_fn,ipairs_fn,ipairs_next_fn,assert_fn,select_fn,unpack_fn,builtin_count};
const char* type_name(const Value& v){
    switch(v.index()){case 0:return "nil";case 1:return "boolean";case 2:return "number";
    case 3:return "string";case 4:return "table";default:return "function";}
}
Value constant(const formats::lua51::Constant& v){
    if(auto x=std::get_if<formats::lua51::Number>(&v))return std::bit_cast<double>(x->bits);
    if(auto x=std::get_if<bool>(&v))return *x;
    if(auto x=std::get_if<std::string>(&v))return *x;
    return std::monostate{};
}
std::optional<double> parse_number(std::string_view t){
    auto ws=[](char c){return c==' '||c=='\t'||c=='\n'||c=='\r'||c=='\v'||c=='\f';};
    while(!t.empty()&&ws(t.front()))t.remove_prefix(1);
    while(!t.empty()&&ws(t.back()))t.remove_suffix(1);
    if(t.empty())return {};
    if(t.front()=='+'){t.remove_prefix(1);if(t.empty()||t.front()=='-'||t.front()=='+')return {};}
    bool neg=t.front()=='-';auto hex=neg?t.substr(1):t;
    if(hex.starts_with("0x")||hex.starts_with("0X")){
        hex.remove_prefix(2);std::uint64_t x{};
        auto result=std::from_chars(hex.data(),hex.data()+hex.size(),x,16);
        if(result.ec!=std::errc{}||result.ptr!=hex.data()+hex.size())return {};
        return neg?-static_cast<double>(x):static_cast<double>(x);
    }
    double x{};auto result=std::from_chars(t.data(),t.data()+t.size(),x,std::chars_format::general);
    if(result.ec!=std::errc{}||result.ptr!=t.data()+t.size()||!std::isfinite(x))return {};
    return x;
}
std::optional<double> try_number(const Value& v){
    if(auto x=std::get_if<double>(&v))return *x;
    if(auto t=std::get_if<std::string>(&v))return parse_number(*t);
    return {};
}
double number(const Value& v){
    auto n=try_number(v);require(bool(n),VmCode::type_error,"expected numeric value");return *n;
}
std::string numeric_string(double n){
    char b[128]{};auto r=std::to_chars(b,b+sizeof(b),n,std::chars_format::general,14);
    require(r.ec==std::errc{},VmCode::unsupported,"number formatting");
    return std::string(b,r.ptr);
}
std::string concat_string(const Value& v){
    if(auto t=std::get_if<std::string>(&v))return *t;
    if(auto n=std::get_if<double>(&v))return numeric_string(*n);
    fail(VmCode::type_error,"non-string concatenation");
}
bool compare(const Value& a,const Value& b,bool le){
    if(auto n=std::get_if<double>(&a)){
        auto r=std::get_if<double>(&b);require(r!=nullptr,VmCode::type_error,"incompatible comparison");
        return le?*n<=*r:*n<*r;
    }
    if(auto n=std::get_if<std::string>(&a)){
        auto r=std::get_if<std::string>(&b);require(r!=nullptr,VmCode::type_error,"incompatible comparison");
        return le?*n<=*r:*n<*r;
    }
    fail(VmCode::type_error,"unsupported ordering");
}
std::int64_t integer(const Value& v){
    const auto n=number(v);
    require(std::isfinite(n)&&n>=-9007199254740991.&&n<=9007199254740991.,
            VmCode::type_error,"integer range");
    return static_cast<std::int64_t>(n);
}
struct Frame {
    Values registers,varargs;
    std::map<unsigned,Cell> open;
    std::size_t top{},limit;
    explicit Frame(const Prototype& p,std::span<const Value> args,std::size_t cap):
        registers(p.max_stack),top(p.max_stack),limit(cap){
        require(p.max_stack<=cap&&args.size()<=cap,VmCode::budget_exhausted,"register limit");
        auto n=std::min<std::size_t>(p.parameters,args.size());std::copy_n(args.begin(),n,registers.begin());
        if((p.vararg&2)&&args.size()>p.parameters)varargs.assign(args.begin()+p.parameters,args.end());
    }
    Value& reg(std::size_t i){
        require(i<limit,VmCode::budget_exhausted,"dynamic register limit");
        if(i>=registers.size())registers.resize(i+1);
        auto it=open.find(static_cast<unsigned>(i));
        return it==open.end()?registers[i]:*it->second;
    }
    Cell capture(unsigned i){
        if(auto it=open.find(i);it!=open.end())return it->second;
        auto cell=std::make_shared<Value>(reg(i));open.emplace(i,cell);return cell;
    }
    void close(unsigned start){
        for(auto it=open.lower_bound(start);it!=open.end();){
            registers[it->first]=*it->second;it=open.erase(it);
        }
    }
    Values slice(std::size_t first,std::size_t n){
        require(first<=limit&&n<=limit-first,VmCode::budget_exhausted,"dynamic result limit");
        Values out;out.reserve(n);for(std::size_t i=0;i<n;++i)out.push_back(reg(first+i));return out;
    }
    void results(std::size_t at,std::size_t n,const Values& data){
        require(at<=limit&&n<=limit-at,VmCode::budget_exhausted,"result register limit");
        for(std::size_t i=0;i<n;++i)reg(at+i)=i<data.size()?data[i]:Value{};
    }
};
}
struct Vm::Impl {
    VmLimits limits;
    std::vector<Table> tables;
    std::vector<Closure> closures;
    std::size_t entries{},steps{};
    explicit Impl(VmLimits l):limits(l){
        require(l.max_objects>=1&&l.max_registers>=1,VmCode::budget_exhausted,"VM limit");
        tables.emplace_back();
        const std::array<std::pair<std::string_view,Builtin>,9> builtins{{
            {"type",type_fn},{"tonumber",tonumber_fn},{"tostring",tostring_fn},{"next",next_fn},
            {"pairs",pairs_fn},{"ipairs",ipairs_fn},{"assert",assert_fn},{"select",select_fn},{"unpack",unpack_fn}}};
        for(auto [name,id]:builtins)set({0},std::string(name),BuiltinRef{id});
        set({0},std::string("_G"),TableRef{0});
    }
    bool valid(const Value& v) const{
        if(auto t=std::get_if<TableRef>(&v))return t->id<tables.size();
        if(auto c=std::get_if<ClosureRef>(&v))return c->id<closures.size();
        if(auto b=std::get_if<BuiltinRef>(&v))return b->id<builtin_count;
        if(auto t=std::get_if<std::string>(&v))return t->size()<=limits.max_string;
        return true;
    }
    Table& table(TableRef r){require(r.id<tables.size(),VmCode::type_error,"invalid table reference");return tables[r.id];}
    const Table& table(TableRef r) const {require(r.id<tables.size(),VmCode::type_error,"invalid table reference");return tables[r.id];}
    TableRef as_table(const Value& v) const {
        auto ref=std::get_if<TableRef>(&v);require(ref&&ref->id<tables.size(),VmCode::type_error,"table expected");return *ref;
    }
    TableRef create_table(){
        require(tables.size()+closures.size()<limits.max_objects,VmCode::budget_exhausted,"object limit");
        auto ref=TableRef{static_cast<std::uint32_t>(tables.size())};tables.emplace_back();return ref;
    }
    ClosureRef create_closure(Closure c){
        require(tables.size()+closures.size()<limits.max_objects,VmCode::budget_exhausted,"closure limit");
        auto ref=ClosureRef{static_cast<std::uint32_t>(closures.size())};closures.push_back(std::move(c));return ref;
    }
    Value get(TableRef ref,const Value& key) const {
        if(nil(key))return {};
        require(valid_key(key)&&valid(key),VmCode::type_error,"invalid table key");
        auto& t=table(ref);auto it=t.entries.find(key);
        return it==t.entries.end()?Value{}:it->second;
    }
    void set(TableRef ref,Value key,Value val){
        require(valid_key(key)&&valid(key)&&valid(val),VmCode::type_error,"invalid table value/key");
        auto& t=table(ref);auto it=t.entries.find(key);
        if(nil(val)){if(it!=t.entries.end()){t.entries.erase(it);--entries;}return;}
        if(it!=t.entries.end()){it->second=std::move(val);return;}
        require(entries<limits.max_entries,VmCode::budget_exhausted,"table entry limit");
        t.entries.emplace(std::move(key),std::move(val));++entries;
    }
    std::size_t length(TableRef ref) const{
        auto& t=table(ref);std::size_t n=0;
        // A deterministic boundary for arrays; Lua's sparse-table boundary
        // is unspecified. No metatable length hook exists in Lua 5.1.
        while(n<t.entries.size()&&t.entries.contains(Value{double(n+1)}))++n;
        return n;
    }
    Values native(BuiltinRef f,std::span<const Value> args){
        require(f.id<builtin_count,VmCode::type_error,"invalid builtin");
        auto a=[&](std::size_t i)->Value{return i<args.size()?args[i]:Value{};};
        switch(f.id){
            case type_fn:return {std::string(type_name(a(0)))};
            case tonumber_fn:{
                if(args.size()>1&&!nil(a(1))&&number(a(1))!=10)fail(VmCode::unsupported,"tonumber base");
                auto n=try_number(a(0));return {n?Value{*n}:Value{}};
            }
            case tostring_fn:{
                auto v=a(0);
                if(nil(v))return {std::string("nil")};
                if(auto b=std::get_if<bool>(&v))return {std::string(*b?"true":"false")};
                if(auto n=std::get_if<double>(&v))return {numeric_string(*n)};
                if(auto t=std::get_if<std::string>(&v))return {*t};
                fail(VmCode::unsupported,"reference string representation");
            }
            case next_fn:{
                auto ref=as_table(a(0));auto key=a(1);const auto& t=table(ref);
                auto it=t.entries.begin();
                if(!nil(key)){
                    require(valid_key(key)&&valid(key),VmCode::type_error,"next key");
                    it=t.entries.find(key);require(it!=t.entries.end(),VmCode::type_error,"invalid next key");
                    ++it;
                }
                if(it==t.entries.end())return {Value{}};
                return {it->first,it->second};
            }
            case pairs_fn:{auto r=as_table(a(0));return {BuiltinRef{next_fn},r,Value{}};}
            case ipairs_fn:{auto r=as_table(a(0));return {BuiltinRef{ipairs_next_fn},r,0.};}
            case ipairs_next_fn:{
                auto r=as_table(a(0));auto i=integer(a(1));
                require(i<9007199254740991ll,VmCode::type_error,"ipairs index");
                Value key=double(i+1),val=get(r,key);
                if(nil(val))return {Value{}};
                return {key,val};
            }
            case assert_fn:require(truth(a(0)),VmCode::type_error,"assertion failed");return Values(args.begin(),args.end());
            case select_fn:{
                auto first=a(0);if(auto t=std::get_if<std::string>(&first);t&&*t=="#")return {double(args.empty()?0:args.size()-1)};
                auto n=integer(first),total=static_cast<std::int64_t>(args.empty()?0:args.size()-1);
                if(n<0)n=total+n+1;
                require(n>=1,VmCode::type_error,"select index");
                if(n>total)return {};
                return Values(args.begin()+n,args.end());
            }
            case unpack_fn:{
                auto r=as_table(a(0));auto first=nil(a(1))?1:integer(a(1));
                auto last=nil(a(2))?static_cast<std::int64_t>(length(r)):integer(a(2));
                if(last<first)return {};
                require(static_cast<std::uint64_t>(last-first)+1<=limits.max_registers,VmCode::budget_exhausted,"unpack limit");
                Values result;for(auto i=first;i<=last;++i)result.push_back(get(r,Value{double(i)}));return result;
            }
        }
        fail(VmCode::unsupported,"builtin");
    }
    Values call(Value fn,Values args,std::size_t depth){
        require(depth<=limits.max_depth&&args.size()<=limits.max_registers,VmCode::budget_exhausted,"call limit");
        for(auto& v:args)require(valid(v),VmCode::type_error,"invalid argument");
        for(;;){
            if(auto native_ref=std::get_if<BuiltinRef>(&fn))return native(*native_ref,args);
            auto ref=std::get_if<ClosureRef>(&fn);
            require(ref&&ref->id<closures.size(),VmCode::type_error,"function expected");
            // Copy the closure: the arena may grow during nested calls.
            auto closure=closures[ref->id];auto& p=*closure.p;
            require(closure.upvalues.size()==p.upvalues,VmCode::malformed,"upvalue count");
            Frame frame(p,args,limits.max_registers);
            if(p.vararg&4){
                require(p.parameters<p.max_stack,VmCode::malformed,"legacy arg register");
                auto t=create_table();
                for(std::size_t i=0;i<frame.varargs.size();++i)set(t,double(i+1),frame.varargs[i]);
                set(t,std::string("n"),double(frame.varargs.size()));frame.reg(p.parameters)=t;
            }
            Values constants;constants.reserve(p.constants.size());
            for(auto& v:p.constants){auto k=constant(v);require(valid(k),VmCode::budget_exhausted,"constant string limit");constants.push_back(std::move(k));}
            std::size_t pc=0;bool tail=false;
            auto rk=[&](unsigned x)->Value{return x&256?constants[x&255]:frame.reg(x);};
            auto setreg=[&](unsigned at,Value v){require(valid(v),VmCode::budget_exhausted,"value limit");frame.reg(at)=std::move(v);};
            while(!tail){
                require(steps<limits.steps,VmCode::budget_exhausted,"instruction budget");++steps;
                require(pc<p.code.size(),VmCode::malformed,"pc outside prototype");
                auto w=p.code[pc++];unsigned op=w&63,a=(w>>6)&255,b=w>>23,c=(w>>14)&511,bx=w>>14;
                auto jump=[&](){pc=static_cast<std::size_t>(static_cast<std::int64_t>(pc)+bx-131071);};
                auto r=[&](unsigned i)->Value&{return frame.reg(i);};
                switch(op){
                    case 0:setreg(a,r(b));break;
                    case 1:setreg(a,constants[bx]);break;
                    case 2:setreg(a,bool(b));pc+=bool(c);break;
                    case 3:for(auto i=a;i<=b;++i)setreg(i,Value{});break;
                    case 4:setreg(a,*closure.upvalues[b]);break;
                    case 5:setreg(a,get({0},constants[bx]));break;
                    case 6:setreg(a,get(as_table(r(b)),rk(c)));break;
                    case 7:set({0},constants[bx],r(a));break;
                    case 8:*closure.upvalues[b]=r(a);break;
                    case 9:set(as_table(r(a)),rk(b),rk(c));break;
                    case 10:setreg(a,create_table());break;
                    case 11:{
                        auto object=r(b);auto method=get(as_table(object),rk(c));
                        setreg(a+1,object);setreg(a,std::move(method));break;
                    }
                    case 12:case 13:case 14:case 15:case 16:case 17:{
                        const auto x=number(rk(b)),y=number(rk(c));double z{};
                        switch(op){case 12:z=x+y;break;case 13:z=x-y;break;case 14:z=x*y;break;
                            case 15:z=x/y;break;case 16:z=x-std::floor(x/y)*y;break;case 17:z=std::pow(x,y);break;}
                        setreg(a,z);break;
                    }
                    case 18:setreg(a,-number(r(b)));break;
                    case 19:setreg(a,!truth(r(b)));break;
                    case 20:{
                        auto v=r(b);if(auto t=std::get_if<std::string>(&v))setreg(a,double(t->size()));
                        else setreg(a,double(length(as_table(v))));break;
                    }
                    case 21:{
                        std::string result;
                        for(auto i=b;i<=c;++i){
                            auto t=concat_string(r(i));require(t.size()<=limits.max_string-result.size(),VmCode::budget_exhausted,"concat limit");
                            result+=t;
                        }
                        setreg(a,std::move(result));break;
                    }
                    case 22:jump();break;
                    case 23:case 24:case 25:{
                        auto x=rk(b),y=rk(c);bool test=op==23?x==y:compare(x,y,op==25);
                        if(test!=bool(a))++pc;break;
                    }
                    case 26:if(truth(r(a))!=bool(c))++pc;break;
                    case 27:if(truth(r(b))==bool(c))setreg(a,r(b));else ++pc;break;
                    case 28:case 29:{
                        auto function=r(a);
                        require(b||frame.top>=a+1,VmCode::malformed,"open call top");
                        auto n=b?b-1:frame.top-a-1;
                        auto input=frame.slice(a+1,n);
                        if(op==29){frame.close(0);fn=std::move(function);args=std::move(input);tail=true;break;}
                        auto output=call(std::move(function),std::move(input),depth+1);
                        frame.results(a,c?c-1:output.size(),output);
                        frame.top=c?p.max_stack:a+output.size();break;
                    }
                    case 30:{
                        require(b||frame.top>=a,VmCode::malformed,"open return top");
                        return frame.slice(a,b?b-1:frame.top-a);
                    }
                    case 31:{
                        auto step=number(r(a+2)),v=number(r(a))+step,lim=number(r(a+1));
                        setreg(a,v);if(step>0?v<=lim:v>=lim){setreg(a+3,v);jump();}break;
                    }
                    case 32:{
                        auto initial=number(r(a)),lim=number(r(a+1)),step=number(r(a+2));
                        setreg(a,initial-step);setreg(a+1,lim);setreg(a+2,step);jump();break;
                    }
                    case 33:{
                        auto fncopy=r(a);Values input{r(a+1),r(a+2)};
                        auto output=call(std::move(fncopy),std::move(input),depth+1);
                        frame.results(a+3,c,output);frame.top=p.max_stack;
                        if(!nil(r(a+3)))setreg(a+2,r(a+3));else ++pc;break;
                    }
                    case 34:{
                        auto target=as_table(r(a));auto block=std::uint64_t(c);
                        if(!c)block=p.code[pc++];
                        require(block>0,VmCode::malformed,"SETLIST block");
                        require(b||frame.top>=a+1,VmCode::malformed,"SETLIST open top");
                        auto n=b?b:frame.top-a-1;
                        auto start=(block-1)*50;
                        for(std::size_t i=1;i<=n;++i)set(target,double(start+i),r(static_cast<unsigned>(a+i)));
                        frame.top=p.max_stack;break;
                    }
                    case 35:frame.close(a);break;
                    case 36:{
                        auto& child=p.children[bx];Closure nested{closure.owner,&child,{}};
                        for(unsigned i=0;i<child.upvalues;++i){
                            auto cap=p.code[pc++],kind=cap&63,index=cap>>23;
                            nested.upvalues.push_back(kind==0?frame.capture(index):closure.upvalues[index]);
                        }
                        setreg(a,create_closure(std::move(nested)));break;
                    }
                    case 37:{
                        require(p.vararg&2,VmCode::malformed,"VARARG in non-vararg prototype");
                        auto n=b?b-1:frame.varargs.size();
                        frame.results(a,n,frame.varargs);if(!b)frame.top=a+n;break;
                    }
                    default:fail(VmCode::malformed,"unknown opcode");
                }
            }
            // Tail calls reuse this invocation depth and the same global
            // instruction budget rather than recursively growing the host stack.
        }
    }
    VmResult invoke(Value fn,std::span<const Value> args){
        steps=0;
        try{return {VmCode::returned,call(std::move(fn),Values(args.begin(),args.end()),1),steps,{}};}
        catch(const Failure& f){return {f.code,{},steps,f.text};}
    }
};
Vm::Vm(VmLimits l):impl_(std::make_unique<Impl>(l)){}
Vm::~Vm()=default;
Vm::Vm(Vm&&) noexcept=default;
Vm& Vm::operator=(Vm&&) noexcept=default;
VmResult Vm::run(const Prototype& p,std::span<const Value> args){
    try{
        require(!p.upvalues,VmCode::unsupported,"root requires captured upvalues");
        auto owner=std::make_shared<const Prototype>(p);
        (void)formats::lua51::verify_flow(formats::lua51::Chunk{*owner});
        return impl_->invoke(impl_->create_closure({owner,owner.get(),{}}),args);
    }catch(const formats::xui::FormatError& e){return {VmCode::malformed,{},0,e.what()};}
     catch(const Failure& f){return {f.code,{},0,f.text};}
}
VmResult Vm::invoke(const Value& fn,std::span<const Value> args){return impl_->invoke(fn,args);}
Value Vm::global(std::string_view name) const{return impl_->get({0},std::string(name));}
bool Vm::set_global(std::string_view name,Value value){
    try{impl_->set({0},std::string(name),std::move(value));return true;}catch(const Failure&){return false;}
}
std::optional<TableRef> Vm::new_table(){try{return impl_->create_table();}catch(const Failure&){return {};}}
std::optional<Value> Vm::raw_get(TableRef t,const Value& key) const{
    try{return impl_->get(t,key);}catch(const Failure&){return {};}
}
bool Vm::raw_set(TableRef t,Value key,Value value){
    try{impl_->set(t,std::move(key),std::move(value));return true;}catch(const Failure&){return false;}
}
}
