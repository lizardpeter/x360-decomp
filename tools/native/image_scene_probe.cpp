#include "os/xam/xui/image_scene.hpp"
#include "formats/xui_catalog.hpp"
#include "formats/xui_mounts.hpp"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <sstream>
using namespace x360::formats;
using namespace x360::os::xam::xui;
static std::vector<std::uint8_t> read(const char* path){
    std::ifstream in(path,std::ios::binary);if(!in)throw xui::FormatError("input open failed");
    return {std::istreambuf_iterator<char>(in),{}};
}
int main(int argc,char** argv){
    if(argc!=5){std::cerr<<"usage: image_scene_probe IMAGE MANIFEST SHAREDRES OUTPUT_DIRECTORY\n";return 2;}
    try{
        auto image=read(argv[1]),shared_bytes=read(argv[3]);
        std::ifstream manifest(argv[2]);if(!manifest)throw xui::FormatError("manifest open failed");
        std::vector<xui::ResourceDescriptor> descriptors;std::string line;
        while(std::getline(manifest,line)){
            std::istringstream row(line);xui::ResourceDescriptor d;std::string extra;
            if(!(row>>d.id>>d.offset>>d.size)||(row>>extra))throw xui::FormatError("bad manifest");
            descriptors.push_back(std::move(d));
        }
        auto catalog=xui::Catalog::open(std::move(image),descriptors);
        auto shared=xui::Archive::parse(shared_bytes);
        xui::Mounts mounts;mounts.mount("sharedres",shared);
        auto common=catalog.archive("dashcomm"),control=catalog.archive("controlp");
        if(common)mounts.mount("common",*common);
        if(control)mounts.mount("controlpack",*control);
        std::size_t count=0;
        for(auto& d:descriptors){
            auto archive=catalog.archive(d.id);if(!archive)continue;
            for(auto& e:archive->entries()){
                if(e.data.size()<4||std::string_view(reinterpret_cast<const char*>(e.data.data()),4)!="XUIB")continue;
                auto scene=xui::Scene::parse(e.data);
                auto s=parse_image_scene(scene);if(!s)continue;
                std::optional<xui::Bytes> texture;
                if(s->texture_uri.find("://")==std::string::npos)texture=archive->find(s->texture_uri);
                else {auto r=mounts.resolve(s->texture_uri);if(r.state==xui::ResolveState::exact||r.state==xui::ResolveState::normalized)texture=r.data;}
                if(!texture)throw xui::FormatError("missing image scene texture");
                auto rendered=render_image_scene(*s,png::decode(*texture));
                auto file=std::filesystem::path(argv[4])/("scene_"+std::to_string(count)+".rgba");
                std::ofstream out(file,std::ios::binary);
                out.write(reinterpret_cast<const char*>(rendered.rgba.data()),rendered.rgba.size());out.close();
                if(!out)throw xui::FormatError("image scene output failed");
                // Original paths are printed only to the local audit process.
                std::cout<<count<<'\t'<<d.id<<'\t'<<e.name<<'\t'<<rendered.width<<'\t'<<rendered.height<<'\n';++count;
            }
        }
    }catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}
}
