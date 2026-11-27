#include "formats/xui_catalog.hpp"
#include "formats/xui_tree.hpp"
#include "formats/xui_structure.hpp"
#include <algorithm>
#include <fstream>
#include <iostream>
#include <iterator>
#include <sstream>
using namespace x360::formats::xui;
int main(int argc,char** argv){
    if(argc!=4){std::cerr<<"usage: x360_xui_tree_probe SCHEMA IMAGE MANIFEST\n";return 2;}
    std::ifstream schema_file(argv[1]),in(argv[2],std::ios::binary),manifest(argv[3]);
    if(!schema_file||!in||!manifest)return 2;
    try{
        auto schema=ClassSchema::read(schema_file);
        std::vector<std::uint8_t> image((std::istreambuf_iterator<char>(in)),{});
        std::vector<ResourceDescriptor> descriptors;
        std::string line,id;
        while(std::getline(manifest,line)){
            std::istringstream row(line);std::size_t offset,size;
            if(!(row>>id>>offset>>size)||offset>image.size()||size>image.size()-offset)throw FormatError("bad manifest");
            descriptors.push_back({id,offset,size});
        }
        auto catalog=Catalog::open(std::move(image),descriptors);
        std::size_t total=0,parsed=0,legacy=0,failed=0,nodes=0,timelines=0,channels=0,keyframes=0,compounds=0,shared=0,ambiguous=0,header_mismatch=0;
        for(auto& d:descriptors)if(auto archive=catalog.archive(d.id)){
            for(auto& e:archive->entries()){
                if(e.data.size()<4||!std::equal(e.data.begin(),e.data.begin()+4,"XUIB"))continue;
                ++total;
                try{
                    auto scene=Scene::parse(e.data);
                    if(scene.version()!=8){++legacy;continue;}
                    auto tree=SceneTree::parse(scene,schema);
                    auto& s=tree.statistics;
                    nodes+=s.nodes;timelines+=s.timelines;channels+=s.channels;keyframes+=s.keyframes;
                    compounds+=s.compound_lists;shared+=s.shared_lists;ambiguous+=s.ambiguous_targets;
                    auto h=SceneStructure::parse(scene)->header;
                    if(h[1]!=s.inline_properties||h[2]!=s.inline_lists||h[4]!=s.compound_lists||h[7]!=s.timelines||h[11]!=s.objects_with_children)++header_mismatch;
                    ++parsed;
                }catch(const std::exception& ex){++failed;std::cerr<<d.id<<"/"<<e.name<<": "<<ex.what()<<"\n";}
            }
        }
        std::cout<<"total="<<total<<" parsed="<<parsed<<" legacy="<<legacy<<" failed="<<failed<<" nodes="<<nodes
          <<" timelines="<<timelines<<" channels="<<channels<<" keyframes="<<keyframes<<" compounds="<<compounds
          <<" shared_lists="<<shared<<" ambiguous_targets="<<ambiguous<<" header_mismatches="<<header_mismatch<<"\n";
        return failed?1:0;
    }catch(const std::exception& ex){std::cerr<<ex.what()<<"\n";return 2;}
}
