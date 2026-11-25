#include "formats/xui.hpp"
#include "formats/xui_timeline.hpp"
#include "formats/xui_structure.hpp"
#include "formats/lua51.hpp"
#include "formats/xui_catalog.hpp"
#include "formats/xui_values.hpp"
#include "os/xam/xui/geometry.hpp"
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
    std::size_t floats=0,vectors=0,quaternions=0,colors=0,shapes=0,segments=0,paths=0,path_points=0;
    std::size_t marker_scenes=0,markers=0,marker_related=0,marker_max_frame=0,lua_chunks=0;
    x360::formats::lua51::Census lua{};
    std::size_t modern=0,legacy=0,keyp_scenes=0,keyp_tokens=0,keyp_max=0,data_bytes=0,data_root_canvas=0,prefix_extended=0,prefix_32=0,prefix_fields=0,name_records=0;
    std::array<std::size_t,12> prefix_sums{};
    std::string line,id,current;
    try{
        std::vector<ResourceDescriptor> descriptors;
        while(std::getline(manifest,line)){
            std::istringstream row(line);std::size_t offset,size;
            if(!(row>>id>>offset>>size)||offset>image.size()||size>image.size()-offset)throw FormatError("invalid resource manifest");
            descriptors.push_back({id,offset,size});
        }
        auto catalog=Catalog::open(std::move(image),descriptors);
        for(auto& d:descriptors){
            id=d.id;current=id;auto ap=catalog.archive(id);if(!ap)continue;
            const auto& archive=*ap;++archives;
            std::set<std::string_view> seen;
            for(auto& e:archive.entries()){
                ++members;current=id+"/"+std::string(e.name);
                if(!seen.insert(e.name).second){++duplicates;(void)archive.find(e.name);}
                if(magic(e.data,"XUIB")){
                    auto s=Scene::parse(e.data);++scenes;sections+=s.sections().size();scene_strings+=s.strings().size();
                    auto str=*s.section("STRN");if(s.version()==8&&str.size()-6!=s.string_units())++unicode_delta;
                    auto names=TimelineNames::parse(s);if(!names.markers().empty())++marker_scenes;
                    for(auto& m:names.markers()){++markers;marker_related+=bool(m.related_name_index);marker_max_frame=std::max(marker_max_frame,std::size_t(m.frame));}
                    if(auto structure=SceneStructure::parse(s)){
                        ++modern;++data_root_canvas;data_bytes+=s.section("DATA")->size();
                        prefix_fields+=structure->header.size();name_records+=structure->name_record_count();
                        for(std::size_t i=0;i<structure->header.size();++i){auto x=structure->header[i];prefix_sums[i]+=x;prefix_extended+=x>=240;prefix_32+=x>=3840;}
                        keyp_scenes+=!structure->key_tokens.empty();keyp_tokens+=structure->key_tokens.size();
                        for(auto x:structure->key_tokens)keyp_max=std::max(keyp_max,std::size_t(x));
                    }else ++legacy;
                    auto v=SceneValues::parse(s);floats+=v.floats.size();vectors+=v.vectors.size();quaternions+=v.quaternions.size();colors+=v.colors.size();shapes+=v.custom.size();
                    for(auto& shape:v.custom){segments+=shape.segments.size();auto contour=x360::os::xam::xui::flatten_closed_shape(shape);if(!contour.empty()&&contour.front()!=contour.back())throw FormatError("open contour");++paths;path_points+=contour.size();}
                }else if(magic(e.data,"XUIS")){
                    auto t=StringTable::parse(e.data);++localizations;localized_strings+=t.entries().size();
                }else if(magic(e.data,"\x1bLua")){
                    auto c=x360::formats::lua51::census(x360::formats::lua51::Chunk::parse(e.data));++lua_chunks;
                    lua.prototypes+=c.prototypes;lua.words+=c.words;lua.constants+=c.constants;lua.strings+=c.strings;lua.max_depth=std::max(lua.max_depth,c.max_depth);
                    lua.upvalues+=c.upvalues;lua.lines+=c.lines;lua.locals+=c.locals;lua.upvalue_names+=c.upvalue_names;lua.setlist_extra+=c.setlist_extra;
                    for(std::size_t i=0;i<lua.opcodes.size();++i)lua.opcodes[i]+=c.opcodes[i];
                    for(std::size_t i=0;i<lua.constant_types.size();++i)lua.constant_types[i]+=c.constant_types[i];
                }else if(e.name.ends_with(".xur")||e.name.ends_with(".xus")||e.name.ends_with(".lub"))throw FormatError("unexpected resource magic");
            }
        }
        // The audit wrapper verifies the original image identity and all 36
        // resource digests before calling this executable.
        std::cout<<"archives="<<archives<<" members="<<members<<" scenes="<<scenes<<" sections="<<sections
                 <<" scene_strings="<<scene_strings<<" localizations="<<localizations<<" localized_strings="<<localized_strings
                 <<" duplicates="<<duplicates<<" unicode_delta="<<unicode_delta
                 <<" floats="<<floats<<" vectors="<<vectors<<" quaternions="<<quaternions<<" colors="<<colors<<" shapes="<<shapes<<" segments="<<segments<<" paths="<<paths<<" path_points="<<path_points
                 <<" marker_scenes="<<marker_scenes<<" markers="<<markers<<" marker_related="<<marker_related<<" marker_max_frame="<<marker_max_frame
                 <<" lua_chunks="<<lua_chunks<<" lua_prototypes="<<lua.prototypes<<" lua_words="<<lua.words<<" lua_constants="<<lua.constants
                 <<" lua_strings="<<lua.strings<<" lua_depth="<<lua.max_depth<<" lua_upvalues="<<lua.upvalues<<" lua_lines="<<lua.lines
                 <<" lua_locals="<<lua.locals<<" lua_upvalue_names="<<lua.upvalue_names<<" lua_setlist_extra="<<lua.setlist_extra;
        for(std::size_t i=0;i<lua.opcodes.size();++i)std::cout<<" lua_op_"<<i<<"="<<lua.opcodes[i];
        for(std::size_t i=0;i<lua.constant_types.size();++i)std::cout<<" lua_const_"<<i<<"="<<lua.constant_types[i];
        std::cout<<" modern="<<modern<<" legacy="<<legacy<<" keyp_scenes="<<keyp_scenes<<" keyp_tokens="<<keyp_tokens<<" keyp_max="<<keyp_max<<" data_bytes="<<data_bytes<<" data_root_canvas="<<data_root_canvas<<" prefix_extended="<<prefix_extended<<" prefix_32="<<prefix_32<<" prefix_fields="<<prefix_fields<<" name_records="<<name_records;
        for(std::size_t i=0;i<prefix_sums.size();++i)std::cout<<" prefix_sum_"<<i<<"="<<prefix_sums[i];
        std::cout<<'\n';
    }catch(const std::exception& e){std::cerr<<current<<": "<<e.what()<<'\n';return 1;}
}
