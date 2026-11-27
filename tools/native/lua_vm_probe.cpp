#include "os/xam/lua_vm.hpp"
#include "formats/xui_catalog.hpp"
#include <bit>
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <locale>
#include <sstream>
using namespace x360::formats;
using namespace x360::os::xam::lua;
namespace {
using lua51::Prototype;
std::vector<std::uint8_t> read(const char* name){
    std::ifstream in(name,std::ios::binary);if(!in)throw xui::FormatError("input open");
    return {std::istreambuf_iterator<char>(in),{}};
}
unsigned digit(char x){
    if(x>='0'&&x<='9')return x-'0';
    if(x>='a'&&x<='f')return x-'a'+10;
    throw xui::FormatError("argument hex");
}
Value input(std::string_view s){
    if(s=="n")return {};
    if(s=="t")return true;
    if(s=="f")return false;
    if(s.empty())throw xui::FormatError("empty argument");
    if(s.front()=='d')return std::stod(std::string(s.substr(1)));
    if(s.front()=='s'&&(s.size()%2)==1){
        std::string text;
        for(std::size_t i=1;i<s.size();i+=2)text+=static_cast<char>((digit(s[i])<<4)|digit(s[i+1]));
        return text;
    }
    throw xui::FormatError("unknown argument type");
}
void emit(const Value& v){
    if(std::holds_alternative<std::monostate>(v))std::cout<<"n";
    else if(auto b=std::get_if<bool>(&v))std::cout<<(*b?"t":"f");
    else if(auto n=std::get_if<double>(&v))std::cout<<"d"<<std::setprecision(17)<<*n;
    else if(auto t=std::get_if<std::string>(&v)){
        std::cout<<"s";for(unsigned char x:*t)std::cout<<std::hex<<std::setw(2)<<std::setfill('0')<<unsigned(x);
        std::cout<<std::dec;
    }else if(std::holds_alternative<TableRef>(v))std::cout<<"xtable";
    else std::cout<<"xfunction";
    std::cout<<"\n";
}
void put(std::ostream& out,std::uint64_t n,unsigned bytes){
    while(bytes)out.put(static_cast<char>(n>>(8*--bytes)));
}
void string(std::ostream& out,const std::optional<std::string>& value){
    if(!value){put(out,0,4);return;}
    put(out,value->size()+1,4);out.write(value->data(),value->size());out.put(0);
}
void write_function(std::ostream& out,const Prototype& p){
    string(out,p.source);put(out,p.line_defined,4);put(out,p.last_line_defined,4);
    put(out,p.upvalues,1);put(out,p.parameters,1);put(out,p.vararg,1);put(out,p.max_stack,1);
    put(out,p.code.size(),4);for(auto w:p.code)put(out,w,4);
    put(out,p.constants.size(),4);
    for(const auto& k:p.constants){
        if(std::holds_alternative<std::monostate>(k))put(out,0,1);
        else if(auto b=std::get_if<bool>(&k)){put(out,1,1);put(out,*b,1);}
        else if(auto n=std::get_if<lua51::Number>(&k)){put(out,3,1);put(out,n->bits,8);}
        else {put(out,4,1);string(out,std::get<std::string>(k));}
    }
    put(out,p.children.size(),4);for(auto& child:p.children)write_function(out,child);
    // Debug data is irrelevant to function execution and not exported in
    // this local isolated-prototype fixture.
    put(out,0,4);put(out,0,4);put(out,0,4);
}
bool safe_globals(const Prototype& p,unsigned depth=0){
    if(depth>16||p.code.size()>2048)return false;
    constexpr std::array<std::string_view,10> allowed{
        "_G","type","tonumber","tostring","next","pairs","ipairs","assert","select","unpack"};
    auto flow=lua51::verify_flow(p);
    for(auto& node:flow.instructions){
        if(node.opcode==7)return false; // isolated original candidates do not mutate globals
        if(node.opcode==5){
            const auto& name=std::get<std::string>(p.constants[p.code[node.pc]>>14]);
            if(std::find(allowed.begin(),allowed.end(),name)==allowed.end())return false;
        }
    }
    for(auto& child:p.children)if(!safe_globals(child,depth+1))return false;
    return true;
}
void extract(const Prototype& p,const std::filesystem::path& dir,std::size_t& count){
    if(count>=512)return;
    if(!p.upvalues&&p.parameters<=8&&safe_globals(p)){
        auto path=dir/(std::to_string(count)+"-"+std::to_string(p.parameters)+".lub");
        std::ofstream out(path,std::ios::binary);
        constexpr char header[]={0x1b,'L','u','a',0x51,0,0,4,4,4,8,0};
        out.write(header,sizeof(header));write_function(out,p);out.close();
        if(!out)throw xui::FormatError("isolated prototype write");
        ++count;
    }
    for(auto& child:p.children)extract(child,dir,count);
}
}
int main(int argc,char** argv){
    try{
        std::cout.imbue(std::locale::classic());
        if(argc>=3&&std::string_view(argv[1])=="run"){
            auto p=lua51::Chunk::parse(read(argv[2])).main;
            std::vector<Value> args;for(int i=3;i<argc;++i)args.push_back(input(argv[i]));
            Vm vm;auto result=vm.run(p,args);
            if(result.code==VmCode::returned){
                std::cout<<"ok "<<result.values.size()<<"\n";for(auto& v:result.values)emit(v);
            }else{
                const char* code=result.code==VmCode::type_error?"error":result.code==VmCode::budget_exhausted?"budget":
                    result.code==VmCode::malformed?"malformed":"unsupported";
                std::cout<<code<<"\n";
            }
            return 0;
        }
        if(argc==5&&std::string_view(argv[1])=="extract"){
            std::ifstream manifest(argv[3]);if(!manifest)return 2;
            std::vector<xui::ResourceDescriptor> descriptors;std::string line;
            while(std::getline(manifest,line)){
                std::istringstream row(line);xui::ResourceDescriptor d;
                if(!(row>>d.id>>d.offset>>d.size))throw xui::FormatError("bad manifest");
                descriptors.push_back(std::move(d));
            }
            auto catalog=xui::Catalog::open(read(argv[2]),descriptors);
            auto dir=std::filesystem::path(argv[4]);std::filesystem::create_directories(dir);
            std::size_t count=0;
            for(auto& d:descriptors)if(auto a=catalog.archive(d.id))
                for(auto& e:a->entries())if(e.data.size()>=4&&std::string_view(reinterpret_cast<const char*>(e.data.data()),4)=="\x1bLua")
                    extract(lua51::Chunk::parse(e.data).main,dir,count);
            std::cout<<count<<"\n";return 0;
        }
        return 2;
    }catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}
}
