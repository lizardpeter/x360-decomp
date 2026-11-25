#include "formats/xui.hpp"
#include <algorithm>
#include <fstream>
#include <iostream>
#include <iterator>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <vector>
using namespace x360::formats::xui;
static bool magic(Bytes b,std::string_view tag){
    return b.size()>=tag.size()&&std::equal(tag.begin(),tag.end(),b.begin());
}
int main(int argc,char** argv){
    if(argc!=3){std::cerr<<"usage: x360_resource_probe IMAGE MANIFEST\n";return 2;}
    std::ifstream in(argv[1],std::ios::binary),manifest(argv[2]);
    if(!in||!manifest){std::cerr<<"cannot open audit inputs\n";return 2;}
    std::vector<std::uint8_t> image((std::istreambuf_iterator<char>(in)),{});
    std::size_t archives=0,members=0,scenes=0,sections=0,scene_strings=0,localizations=0,localized_strings=0,duplicates=0,unicode_delta=0;
    std::string line,id,current;
    try{
        while(std::getline(manifest,line)){
            std::istringstream row(line);std::size_t offset,size;
            if(!(row>>id>>offset>>size)||offset>image.size()||size>image.size()-offset)throw FormatError("invalid resource manifest");
            current=id;auto bytes=Bytes(image).subspan(offset,size);
            if(!magic(bytes,"XUIZ"))continue;
            auto archive=Archive::parse(bytes);++archives;
            std::set<std::string_view> seen;
            for(auto& e:archive.entries()){
                ++members;current=id+"/"+std::string(e.name);
                if(!seen.insert(e.name).second){++duplicates;(void)archive.find(e.name);}
                if(magic(e.data,"XUIB")){
                    auto s=Scene::parse(e.data);++scenes;sections+=s.sections().size();scene_strings+=s.strings().size();
                    auto str=*s.section("STRN");if(str.size()-6!=s.string_units())++unicode_delta;
                }else if(magic(e.data,"XUIS")){
                    auto t=StringTable::parse(e.data);++localizations;localized_strings+=t.entries().size();
                }else if(e.name.ends_with(".xur")||e.name.ends_with(".xus"))throw FormatError("unexpected resource magic");
            }
        }
        // The audit wrapper verifies the original image identity and all 36
        // resource digests before calling this executable.
        std::cout<<"archives="<<archives<<" members="<<members<<" scenes="<<scenes<<" sections="<<sections
                 <<" scene_strings="<<scene_strings<<" localizations="<<localizations<<" localized_strings="<<localized_strings
                 <<" duplicates="<<duplicates<<" unicode_delta="<<unicode_delta<<'\n';
    }catch(const std::exception& e){std::cerr<<current<<": "<<e.what()<<'\n';return 1;}
}
