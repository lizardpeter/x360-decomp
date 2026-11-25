#include "formats/png.hpp"
#include "formats/xui_catalog.hpp"
#include <fstream>
#include <iostream>
#include <iterator>
#include <sstream>
using namespace x360::formats;
int main(int argc,char** argv){
    if(argc!=4){std::cerr<<"usage: texture_probe IMAGE MANIFEST RGBA_OUTPUT\n";return 2;}
    std::ifstream in(argv[1],std::ios::binary),manifest(argv[2]);
    std::ofstream out(argv[3],std::ios::binary);
    if(!in||!manifest||!out)return 2;
    std::vector<std::uint8_t> image((std::istreambuf_iterator<char>(in)),{});
    std::string line,id,current;std::size_t images=0,pixels=0;
    try{
        std::vector<xui::ResourceDescriptor> descriptors;
        while(std::getline(manifest,line)){
            std::istringstream row(line);std::size_t offset,size;std::string extra;
            if(!(row>>id>>offset>>size)||(row>>extra))throw xui::FormatError("bad texture manifest");
            descriptors.push_back({id,offset,size});
        }
        auto catalog=xui::Catalog::open(std::move(image),descriptors);
        for(auto& d:descriptors){
            auto archive=catalog.archive(d.id);if(!archive)continue;
            for(auto& e:archive->entries()){
                current=d.id+"/"+e.name;
                constexpr std::array<std::uint8_t,4> png_magic{137,80,78,71};
                bool is_png=e.data.size()>=4&&std::equal(png_magic.begin(),png_magic.end(),e.data.begin());
                if(!is_png){if(e.name.ends_with(".png"))throw xui::FormatError("PNG magic mismatch");continue;}
                auto texture=png::decode(e.data);
                ++images;pixels+=std::size_t(texture.width)*texture.height;
                out.write(reinterpret_cast<const char*>(texture.rgba.data()),texture.rgba.size());
                if(!out)throw xui::FormatError("texture output failed");
            }
        }
        out.close();if(!out)throw xui::FormatError("texture output close failed");
        std::cout<<images<<" "<<pixels<<"\n";
    }catch(const std::exception& e){std::cerr<<current<<": "<<e.what()<<"\n";return 1;}
}
