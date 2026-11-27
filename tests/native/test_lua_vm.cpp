#include "os/xam/lua_vm.hpp"
#include <bit>
#include <cstdlib>
#include <iostream>
#include <limits>
using namespace x360::os::xam::lua;
using x360::formats::lua51::Prototype;
using x360::formats::lua51::Number;
static void check(bool b,const char* why){if(!b){std::cerr<<why<<'\n';std::exit(1);}}
static unsigned abc(unsigned op,unsigned a,unsigned b,unsigned c){return op|(a<<6)|(c<<14)|(b<<23);}
static unsigned abx(unsigned op,unsigned a,unsigned x){return op|(a<<6)|(x<<14);}
static unsigned jump(unsigned op,unsigned a,int x){return abx(op,a,static_cast<unsigned>(x+131071));}
static Number num(double n){return {std::bit_cast<std::uint64_t>(n)};}
static void result(VmResult r,std::initializer_list<Value> values){
    if(r.code!=VmCode::returned||r.values!=std::vector<Value>(values)){
        std::cerr<<"VM result failure: "<<r.detail<<" steps="<<r.steps<<'\n';std::exit(1);
    }
}
int main(){
    Vm vm;
    Prototype p;p.max_stack=8;
    p.constants={num(12),num(30),std::string("x"),std::string("saved")};
    p.code={abc(10,0,0,0),abc(9,0,258,256),abc(6,1,0,258),abc(12,1,1,257),
        abx(7,1,3),abx(5,2,3),abc(30,2,2,0)};
    result(vm.run(p),{42.});check(vm.global("saved")==Value{42.},"global state");
    auto table=vm.new_table();check(bool(table),"create table");
    check(vm.raw_set(*table,1.,std::string("a"))&&vm.raw_set(*table,2.,std::string("b")),"raw table");
    check(!vm.raw_set(*table,Value{},1.)&&!vm.raw_set(*table,std::numeric_limits<double>::quiet_NaN(),1.),"invalid keys");
    p.parameters=1;p.code={abc(20,1,0,0),abc(30,1,2,0)};
    result(vm.run(p,std::array<Value,1>{*table}),{2.});
    check(vm.raw_set(*table,1.,Value{})&&vm.raw_get(*table,1.)==std::optional<Value>{Value{}},"nil deletes");
    Prototype child;child.max_stack=3;child.upvalues=1;child.parameters=1;
    child.code={abc(4,1,0,0),abc(12,1,1,0),abc(8,1,0,0),abc(30,1,2,0)};
    p={};p.max_stack=5;p.children={child};p.constants={num(10),num(2),num(3)};
    p.code={abx(1,0,0),abx(36,1,0),abc(0,0,0,0),abc(30,1,2,0)};
    auto closure=vm.run(p);check(closure.code==VmCode::returned&&std::holds_alternative<ClosureRef>(closure.values[0]),"closure capture");
    auto fn=closure.values[0];result(vm.invoke(fn,std::array<Value,1>{2.}),{12.});result(vm.invoke(fn,std::array<Value,1>{3.}),{15.});
    // CLOSE closes the cell; a later register reuse cannot affect it.
    p.code={abx(1,0,0),abx(36,1,0),abc(0,0,0,0),abc(35,0,0,0),abx(1,0,1),abc(30,1,2,0)};
    auto closed=vm.run(p);check(closed.code==VmCode::returned,"close");
    result(vm.invoke(closed.values[0],std::array<Value,1>{3.}),{13.});
    // Fixed and open calls, nested varargs, and tail calls.
    child={};child.max_stack=2;child.vararg=2;child.code={abc(37,0,0,0),abc(30,0,0,0)};
    p={};p.max_stack=6;p.children={child};p.constants={num(7),num(8),num(9)};
    p.code={abx(36,0,0),abx(1,1,0),abx(1,2,1),abx(1,3,2),abc(28,0,4,0),abc(30,0,0,0)};
    result(vm.run(p),{7.,8.,9.});
    p.code={abx(36,0,0),abx(1,1,0),abx(1,2,1),abc(29,0,3,0)};
    result(vm.run(p),{7.,8.});
    p.code={abx(36,0,0),abx(1,1,0),abc(28,0,2,3),abc(30,0,3,0)};
    result(vm.run(p),{7.,Value{}});
    // SETLIST and TFORLOOP over an actual table via the registered ipairs.
    p={};p.max_stack=9;p.constants={num(2),num(3),num(5),std::string("ipairs"),num(0)};
    p.code={abc(10,0,0,0),abx(1,1,0),abx(1,2,1),abx(1,3,2),abc(34,0,3,1),
        abx(5,1,3),abc(0,2,0,0),abc(28,1,2,4),abx(1,6,4),
        jump(22,0,1),abc(12,6,6,5),abc(33,1,0,2),jump(22,0,-3),abc(30,6,2,0)};
    result(vm.run(p),{10.});
    // Numeric loops and string coercion.
    p={};p.max_stack=6;p.constants={std::string("1"),num(5),num(1),num(0)};
    p.code={abx(1,0,0),abx(1,1,1),abx(1,2,2),abx(1,4,3),jump(32,0,1),
        abc(12,4,4,3),jump(31,0,-2),abc(30,4,2,0)};
    result(vm.run(p),{15.});
    p={};p.max_stack=4;p.constants={std::string("v="),num(12.5)};
    p.code={abx(1,0,0),abx(1,1,1),abc(21,2,0,1),abc(30,2,2,0)};
    result(vm.run(p),{std::string("v=12.5")});
    p={};p.max_stack=1;p.code={jump(22,0,-1)};
    Vm bounded({17});check(bounded.run(p).code==VmCode::budget_exhausted,"instruction limit");
    p.code={abx(1,0,999),abc(30,0,2,0)};check(vm.run(p).code==VmCode::malformed,"malformed constant");
    std::cout<<"Lua 5.1 VM tables, closures, upvalues, calls, tail calls, varargs, iteration, loops and limits passed\n";
}
