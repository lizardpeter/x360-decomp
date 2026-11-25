#include "formats/xui_mounts.hpp"
#include "formats/xui_catalog.hpp"
#include <array>
#include <fstream>
#include <iostream>
#include <iterator>
#include <sstream>
using namespace x360::formats::xui;
static std::vector<std::uint8_t> read(const char* path){
    std::ifstream in(path,std::ios::binary);if(!in)throw FormatError("input open failed");
    return {std::istreambuf_iterator<char>(in),{}};
}
int main(int argc,char** argv){
    if(argc!=4){std::cerr<<"usage: uri_probe IMAGE MANIFEST SHAREDRES\n";return 2;}
    try{
        auto image=read(argv[1]),shared_bytes=read(argv[3]);
        std::ifstream manifest(argv[2]);if(!manifest)throw FormatError("manifest open failed");
        std::vector<ResourceDescriptor> descriptors;std::string line;
        while(std::getline(manifest,line)){
            std::istringstream row(line);ResourceDescriptor d;std::string extra;
            if(!(row>>d.id>>d.offset>>d.size)||(row>>extra))throw FormatError("bad manifest");
            descriptors.push_back(std::move(d));
        }
        auto catalog=Catalog::open(std::move(image),descriptors);
        auto shared=Archive::parse(shared_bytes);
        auto common=catalog.archive("dashcomm"),control=catalog.archive("controlp");
        if(!common||!control)throw FormatError("missing original archive");
        Mounts mounts;mounts.mount("common",*common);mounts.mount("controlpack",*control);mounts.mount("sharedres",shared);
        std::array<std::size_t,6> counts{};
        for(auto& d:descriptors){
            auto archive=catalog.archive(d.id);if(!archive)continue;
            for(auto& e:archive->entries()){
                if(e.data.size()<4||std::string_view(reinterpret_cast<const char*>(e.data.data()),4)!="XUIB")continue;
                auto scene=Scene::parse(e.data);
                for(auto& s:scene.strings()){
                    std::istringstream lines(s);std::string uri;
                    while(std::getline(lines,uri)){
                        if(!uri.empty()&&uri.back()=='\r')uri.pop_back();
                        if(uri.find("://")==std::string::npos)continue;
                        auto r=mounts.resolve(uri);++counts[static_cast<unsigned>(r.state)];
                    }
                }
            }
        }
        for(std::size_t i=0;i<counts.size();++i)std::cout<<(i?" ":"")<<counts[i];
        std::cout<<"\n";
    }catch(const std::exception& e){std::cerr<<e.what()<<"\n";return 1;}
}
