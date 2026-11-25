#include "os/xam/lua_scalar.hpp"
#include "formats/xui_catalog.hpp"
#include <bit>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <sstream>
using namespace x360::formats;
using namespace x360::os::xam::lua;
static void emit(std::ostream& o,const Scalar& s){
    if(std::holds_alternative<std::monostate>(s))o<<'n';
    else if(auto b=std::get_if<bool>(&s))o<<(*b?'t':'f');
    else if(auto n=std::get_if<double>(&s))o<<'d'<<std::hex<<std::setfill('0')<<std::setw(16)<<std::bit_cast<std::uint64_t>(*n)<<std::dec;
    else {o<<'s';for(unsigned char c:std::get<std::string>(s))o<<std::hex<<std::setw(2)<<std::setfill('0')<<unsigned(c);o<<std::dec;}
}
static void audit(const lua51::Prototype& p,std::ostream& output,std::size_t& count,std::size_t& ok,std::size_t& errors){
    if(eligible(p)){
        const std::array<Scalar,20> args{std::monostate{},false,true,0.,1.,-1.,2.,16384.,2348810240.,2365587455.,2147500037.,2147942487.,134246400.,2148007935.,std::string{},std::string("*"),std::string("."),std::string("abc"),std::string("\\"),std::string("1")};
        ++count;
        for(auto& arg:args){
            std::vector<Scalar> in(p.parameters,arg);
            auto result=execute(p,in);
            if(result.code==ResultCode::returned){
                ++ok;output<<"ok:";
                for(std::size_t i=0;i<result.values.size();++i){if(i)output<<',';emit(output,result.values[i]);}output<<'\n';
            }else if(result.code==ResultCode::type_error){++errors;output<<"type\n";}
            else throw xui::FormatError("unexpected original scalar VM outcome");
        }
    }
    for(auto& child:p.children)audit(child,output,count,ok,errors);
}
int main(int argc,char** argv){
    if(argc!=4)return 2;
    try{
        std::ifstream in(argv[1],std::ios::binary),manifest(argv[2]);std::ofstream out(argv[3],std::ios::binary);
        if(!in||!manifest||!out)return 2;
        std::vector<std::uint8_t> image((std::istreambuf_iterator<char>(in)),{});
        std::vector<xui::ResourceDescriptor> descriptors;std::string line;
        while(std::getline(manifest,line)){
            std::istringstream row(line);xui::ResourceDescriptor d;
            if(!(row>>d.id>>d.offset>>d.size))throw xui::FormatError("bad manifest");
            descriptors.push_back(std::move(d));
        }
        auto catalog=xui::Catalog::open(std::move(image),descriptors);
        std::size_t count=0,ok=0,errors=0;
        for(auto& d:descriptors)if(auto a=catalog.archive(d.id))
            for(auto& e:a->entries())if(e.data.size()>=4&&std::string_view(reinterpret_cast<const char*>(e.data.data()),4)=="\x1bLua")
                audit(lua51::Chunk::parse(e.data).main,out,count,ok,errors);
        out.close();if(!out)return 1;
        std::cout<<count<<" "<<ok<<" "<<errors<<"\n";
    }catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}
}
