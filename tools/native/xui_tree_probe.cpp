#include "formats/xui_catalog.hpp"
#include "formats/xui_tree.hpp"
#include "formats/xui_structure.hpp"
#include <algorithm>
#include <fstream>
#include <iostream>
#include <iterator>
#include <iomanip>
#include <cmath>
#include <type_traits>
#include <string_view>
#include <cctype>
#include <sstream>
using namespace x360::formats::xui;
namespace {
// Metadata only: no original image, Lua bytecode, or localized text is exported.
// Retain explicitly authored values, never infer absent defaults.
bool layout_property(std::string_view name){
    for(auto candidate:{"Width","Height","Position","Scale","Rotation","Pivot","Anchor",
                       "ClipChildren","Opacity","Show","PointSize","TextStyle","TextScale",
                       "LineSpacingAdjust","SizeToText","DataAssociation","Id","Font","Visual",
                       "Text","CenterPivot","Alignment","TextAlignment"})
        if(name==candidate)return true;
    return false;
}
std::string identifier(std::string_view s){
    if(s.empty())return "-";
    if(s.size()>160)return "<long>";
    for(unsigned char c:s)if(!(std::isalnum(c)||c=='_'||c=='-'||c=='.'||c=='/'||c=='\\'||c==':'||c==' '))return "<nonidentifier>";
    return std::string(s);
}
std::string value_string(const PropertyValue& value,std::string_view name){
    std::ostringstream out;
    out<<std::setprecision(9);
    std::visit([&](auto const& item){
        using T=std::decay_t<decltype(item)>;
        if constexpr(std::is_same_v<T,bool>)out<<(item?"true":"false");
        else if constexpr(std::is_arithmetic_v<T>)out<<item;
        else if constexpr(std::is_same_v<T,Vec3>||std::is_same_v<T,Quaternion>){
            bool first=true;for(float f:item){if(!first)out<<',';first=false;out<<f;}
        }else if constexpr(std::is_same_v<T,std::string>){
            if(name=="Id"||name=="Font"||name=="Visual")out<<identifier(item);
            else out<<"string-bytes="<<item.size();
        }else out<<"<nonlayout>";
    },value);
    return out.str();
}
void audit_node(const Element& node,std::string_view resource,std::string_view member,
                std::string_view parent){
    auto prefix=[&](std::string_view kind){
        std::cout<<kind<<'\\t'<<std::quoted(std::string(resource))<<'\\t'
                 <<std::quoted(std::string(member))<<'\\t'<<node.index<<'\\t';
    };
    prefix("node");std::cout<<parent<<'\\t'<<std::quoted(node.class_name)<<"\\n";
    if(node.properties)for(auto& p:*node.properties)if(layout_property(p.name))
        for(std::size_t i=0;i<p.values.size();++i){
            prefix("property");
            std::cout<<std::quoted(p.owner)<<'\\t'<<std::quoted(p.name)<<'\\t'
                     <<i<<'\\t'<<std::quoted(value_string(p.values[i],p.name))<<"\\n";
        }
    for(auto& timeline:node.timelines)for(std::size_t i=0;i<timeline.channels.size();++i){
        auto& channel=timeline.channels[i];
        if(channel.path.empty()||!layout_property(channel.path.back()))continue;
        std::string path;
        for(auto& part:channel.path){if(!path.empty())path+='.';path+=part;}
        for(auto& frame:timeline.frames){
            if(i>=frame.values.size())throw FormatError("missing timeline value");
            prefix("keyframe");
            std::cout<<timeline.target_node<<'\\t'<<std::quoted(path)<<'\\t'
                     <<frame.metadata.frame<<'\\t'<<unsigned(frame.metadata.flags)<<'\\t'
                     <<std::quoted(value_string(frame.values[i],channel.path.back()))<<"\\n";
        }
    }
    for(auto& child:node.children)audit_node(child,resource,member,std::to_string(node.index));
}
}
int main(int argc,char** argv){
    const bool layout=argc==5 && std::string_view(argv[4])=="--header-layout";
    if(argc!=4&&!layout){std::cerr<<"usage: x360_xui_tree_probe SCHEMA IMAGE MANIFEST [--header-layout]\n";return 2;}
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
                    if(layout&&(d.id=="epix"||d.id=="socxzp"))audit_node(tree.root,d.id,e.name,"-");
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
