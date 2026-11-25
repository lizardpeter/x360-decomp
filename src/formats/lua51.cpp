#include "formats/lua51.hpp"
#include <algorithm>
namespace x360::formats::lua51 {
namespace {
using xui::FormatError;
struct Reader {
    Bytes bytes;std::size_t pos{};
    Bytes take(std::size_t n){
        if(pos>bytes.size()||n>bytes.size()-pos)throw FormatError("truncated Lua chunk");
        auto b=bytes.subspan(pos,n);pos+=n;return b;
    }
    std::uint8_t u8(){return take(1)[0];}
    std::uint32_t u32(){std::uint32_t v=0;for(auto b:take(4))v=(v<<8)|b;return v;}
    std::uint64_t u64(){std::uint64_t v=0;for(auto b:take(8))v=(v<<8)|b;return v;}
    std::size_t count(std::size_t min_bytes){
        auto n=u32();
        if(n>(bytes.size()-pos)/min_bytes)throw FormatError("impossible Lua count");
        return n;
    }
    std::optional<std::string> string(){
        auto n=u32();if(!n)return std::nullopt;
        auto b=take(n);if(b.back()!=0)throw FormatError("unterminated Lua string");
        return std::string(reinterpret_cast<const char*>(b.data()),b.size()-1);
    }
    std::string required_string(){
        auto s=string();if(!s)throw FormatError("missing Lua string");return std::move(*s);
    }
    Prototype function(unsigned depth){
        if(depth>64)throw FormatError("Lua prototype nesting limit");
        Prototype f;f.source=string();f.line_defined=u32();f.last_line_defined=u32();
        f.upvalues=u8();f.parameters=u8();f.vararg=u8();f.max_stack=u8();
        if(!f.max_stack||f.parameters>f.max_stack)throw FormatError("invalid Lua stack size");
        auto n=count(4);f.code.reserve(n);for(std::size_t i=0;i<n;++i)f.code.push_back(u32());
        // SETLIST with C=0 consumes a following data word, not an opcode.
        for(std::size_t i=0;i<f.code.size();++i){
            auto w=f.code[i],op=w&63u;
            if(op>=38)throw FormatError("unknown Lua opcode");
            if(op==34&&((w>>14)&511u)==0&&++i>=f.code.size())throw FormatError("missing Lua SETLIST word");
        }
        n=count(1);f.constants.reserve(n);
        for(std::size_t i=0;i<n;++i){
            switch(u8()){
                case 0:f.constants.emplace_back(std::monostate{});break;
                case 1:{auto b=u8();if(b>1)throw FormatError("invalid Lua boolean");f.constants.emplace_back(bool(b));break;}
                case 3:f.constants.emplace_back(Number{u64()});break;
                case 4:f.constants.emplace_back(required_string());break;
                default:throw FormatError("unsupported Lua constant");
            }
        }
        n=count(28);f.children.reserve(n);for(std::size_t i=0;i<n;++i)f.children.push_back(function(depth+1));
        n=count(4);if(n&&n!=f.code.size())throw FormatError("Lua line count mismatch");
        f.lines.reserve(n);for(std::size_t i=0;i<n;++i)f.lines.push_back(u32());
        n=count(12);f.locals.reserve(n);
        for(std::size_t i=0;i<n;++i){
            Local l{required_string(),u32(),u32()};
            if(l.start_pc>l.end_pc||l.end_pc>f.code.size())throw FormatError("invalid Lua local lifetime");
            f.locals.push_back(std::move(l));
        }
        n=count(4);if(n&&n!=f.upvalues)throw FormatError("Lua upvalue name count mismatch");
        f.upvalue_names.reserve(n);for(std::size_t i=0;i<n;++i)f.upvalue_names.push_back(required_string());
        return f;
    }
};
void measure(const Prototype& f,Census& c,std::size_t depth){
    ++c.prototypes;c.words+=f.code.size();c.constants+=f.constants.size();c.max_depth=std::max(c.max_depth,depth);
    c.upvalues+=f.upvalues;c.lines+=f.lines.size();c.locals+=f.locals.size();c.upvalue_names+=f.upvalue_names.size();
    c.strings+=bool(f.source)+f.locals.size()+f.upvalue_names.size();
    for(auto& k:f.constants){++c.constant_types[k.index()];if(std::holds_alternative<std::string>(k))++c.strings;}
    for(std::size_t i=0;i<f.code.size();++i){
        auto w=f.code[i],op=w&63u;
        if(op>=38)throw FormatError("invalid opcode in census");
        ++c.opcodes[op];
        if(op==34&&((w>>14)&511u)==0){if(++i>=f.code.size())throw FormatError("missing SETLIST word");++c.setlist_extra;}
    }
    for(auto& child:f.children)measure(child,c,depth+1);
}
}
Chunk Chunk::parse(Bytes input){
    constexpr std::array<std::uint8_t,12> header{0x1b,'L','u','a',0x51,0,0,4,4,4,8,0};
    Reader r{input};
    auto h=r.take(header.size());if(!std::equal(h.begin(),h.end(),header.begin()))throw FormatError("unsupported Lua 5.1 ABI");
    Chunk c{r.function(1)};
    if(r.pos!=input.size())throw FormatError("trailing Lua chunk data");
    return c;
}
Census census(const Chunk& chunk){Census c;measure(chunk.main,c,1);return c;}
}
