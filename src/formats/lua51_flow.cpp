#include "formats/lua51_flow.hpp"
#include <algorithm>
#include <limits>
namespace x360::formats::lua51 {
namespace {
using xui::FormatError;
void require(bool ok,const char* why){if(!ok)throw FormatError(why);}
void collect(const Prototype& p,FlowCensus& c,unsigned depth){
    require(depth<=64,"flow nesting limit");
    auto flow=verify_flow(p);++c.prototypes;c.instructions+=flow.instructions.size();
    c.capture_words+=flow.capture_words;c.extra_words+=flow.extra_words;c.reachable+=flow.reachable;
    c.unreachable+=flow.instructions.size()-flow.reachable;
    for(auto& n:flow.instructions){c.edges+=n.successors.size();c.branch_nodes+=n.successors.size()>1;c.terminal_nodes+=n.successors.empty();}
    for(auto& child:p.children)collect(child,c,depth+1);
}
}
FunctionFlow verify_flow(const Prototype& p){
    const auto& code=p.code;const auto n=code.size();
    require(n&&n<=std::numeric_limits<std::uint32_t>::max(),"invalid Lua code size");
    require(p.max_stack>0&&p.parameters<=p.max_stack,"invalid Lua stack");
    auto reg=[&](unsigned a){require(a<p.max_stack,"Lua register out of bounds");};
    auto k=[&](unsigned a){require(a<p.constants.size(),"Lua constant out of bounds");};
    auto rk=[&](unsigned a){if(a&256)k(a&255);else reg(a);};
    auto up=[&](unsigned a){require(a<p.upvalues,"Lua upvalue out of bounds");};
    FunctionFlow result;
    std::vector<std::size_t> index(n,std::numeric_limits<std::size_t>::max());
    for(std::size_t i=0;i<n;){
        auto w=code[i];unsigned op=w&63,a=(w>>6)&255,c=(w>>14)&511,b=w>>23,bx=w>>14;
        auto sbx=static_cast<std::int64_t>(bx)-131071;
        auto next=i+1;
        require(op<38,"invalid Lua opcode");
        if(op==36){
            reg(a);require(bx<p.children.size(),"Lua child prototype out of bounds");
            auto count=p.children[bx].upvalues;
            require(count<=n-next,"truncated Lua closure captures");
            for(auto j=next;j<next+count;++j){
                auto cap=code[j],kind=cap&63,operand=cap>>23;
                if(kind==0)reg(operand);
                else if(kind==4)up(operand);
                else throw FormatError("invalid Lua closure capture");
                ++result.capture_words;
            }
            next+=count;
        }else if(op==34&&!c){
            require(next<n,"truncated Lua SETLIST operand");
            ++next;++result.extra_words;
        }
        switch(op){
            case 0:reg(a);reg(b);break;
            case 1:reg(a);k(bx);break;
            case 2:reg(a);require(b<=1&&c<=1,"invalid LOADBOOL flags");break;
            case 3:reg(a);reg(b);require(a<=b,"invalid LOADNIL range");break;
            case 4:case 8:reg(a);up(b);break;
            case 5:case 7:reg(a);k(bx);require(std::holds_alternative<std::string>(p.constants[bx]),"Lua global name is not a string");break;
            case 6:reg(a);reg(b);rk(c);break;
            case 9:reg(a);rk(b);rk(c);break;
            case 10:reg(a);break;
            case 11:reg(a);reg(a+1);reg(b);rk(c);break;
            case 12:case 13:case 14:case 15:case 16:case 17:reg(a);rk(b);rk(c);break;
            case 18:case 19:case 20:reg(a);reg(b);break;
            case 21:reg(a);reg(b);reg(c);require(b<c,"invalid CONCAT range");break;
            case 22:break;
            case 23:case 24:case 25:require(a<=1,"invalid comparison flag");rk(b);rk(c);break;
            case 26:reg(a);require(c<=1,"invalid TEST flag");break;
            case 27:reg(a);reg(b);require(c<=1,"invalid TESTSET flag");break;
            case 28:case 29:reg(a);if(b)reg(a+b-1);if(c>1)reg(a+c-2);break;
            case 30:reg(a);if(b>1)reg(a+b-2);break;
            case 31:case 32:reg(a+3);break;
            case 33:require(c>=1,"invalid TFORLOOP count");reg(a+2+c);break;
            case 34:reg(a);if(b)reg(a+b);break;
            case 35:reg(a);break;
            case 36:break;
            case 37:reg(a);if(b>1)reg(a+b-2);break;
        }
        InstructionFlow node{static_cast<std::uint32_t>(i),static_cast<std::uint8_t>(op),{}};
        auto edge=[&](std::int64_t target){
            require(target>=0&&static_cast<std::uint64_t>(target)<n,"Lua branch outside prototype");
            node.successors.push_back(static_cast<std::uint32_t>(target));
        };
        const auto jump=static_cast<std::int64_t>(i)+1+sbx;
        if(op==29||op==30){}
        else if(op==22||op==32)edge(jump);
        else if(op==31){edge(next);edge(jump);}
        else if((op>=23&&op<=27)||op==33){
            require(next<n&&(code[next]&63)==22,"Lua conditional missing paired JMP");
            edge(next);edge(next+1);
        }else if(op==2&&c)edge(next+1);
        else edge(next);
        index[i]=result.instructions.size();
        result.instructions.push_back(std::move(node));i=next;
    }
    for(auto& node:result.instructions)
        for(auto successor:node.successors)
            require(index[successor]!=std::numeric_limits<std::size_t>::max(),"Lua branch into embedded operands");
    std::vector<bool> visited(result.instructions.size());
    std::vector<std::size_t> work{0};
    while(!work.empty()){
        auto i=work.back();work.pop_back();if(visited[i])continue;
        visited[i]=true;++result.reachable;
        for(auto successor:result.instructions[i].successors)work.push_back(index[successor]);
    }
    return result;
}
FlowCensus verify_flow(const Chunk& chunk){FlowCensus c;collect(chunk.main,c,1);return c;}
}
