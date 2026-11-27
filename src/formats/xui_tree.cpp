#include "formats/xui_tree.hpp"
#include "formats/xui_structure.hpp"
#include <algorithm>
#include <bit>
#include <limits>
#include <set>
#include <sstream>

namespace x360::formats::xui {
namespace {
constexpr std::size_t max_nodes=100000,max_items=1000000,max_depth=64;
[[noreturn]] void bad(std::string_view msg){throw FormatError(std::string(msg));}
PropertyType type_of(std::string_view s){
    if(s=="bool")return PropertyType::boolean;
    if(s=="integer")return PropertyType::integer;
    if(s=="unsigned")return PropertyType::unsigned_integer;
    if(s=="float")return PropertyType::real;
    if(s=="string")return PropertyType::string;
    if(s=="color")return PropertyType::color;
    if(s=="vector")return PropertyType::vector;
    if(s=="quaternion")return PropertyType::quaternion;
    if(s=="object")return PropertyType::object;
    if(s=="custom")return PropertyType::custom;
    bad("unknown schema type");
}
struct Cursor {
    Bytes bytes;
    std::size_t pos{};
    bool done() const{return pos==bytes.size();}
    std::uint8_t byte(){if(done())bad("truncated XUI tree");return bytes[pos++];}
    std::uint32_t packed(){
        auto a=byte();
        if(a<240)return a;
        if(a==255){
            std::uint32_t n=0;for(int i=0;i<4;++i)n=(n<<8)|byte();
            if(n<3840)bad("noncanonical wide integer");
            return n;
        }
        auto n=std::uint32_t(a-240)*256+byte();
        if(n<240)bad("noncanonical compact integer");
        return n;
    }
};
std::size_t count(Cursor& c,std::size_t limit=max_items){
    auto n=c.packed();if(n>limit)bad("XUI count limit");return n;
}
template<class T> const T& at(const std::vector<T>& v,std::size_t i){
    if(i>=v.size())bad("XUI pool index out of range");
    return v[i];
}
std::string_view compound_class(std::string_view name){
    if(name=="Fill")return "XuiFigureFill";
    if(name=="Gradient")return "XuiFigureFillGradient";
    if(name=="Stroke")return "XuiFigureStroke";
    bad("unknown compound property class");
}
struct Parser {
    const Scene& scene;
    const ClassSchema& schema;
    SceneStructure structure;
    SceneTree result;
    Cursor data;
    std::vector<std::shared_ptr<const PropertyList>> property_lists;
    std::vector<std::size_t> shape_offsets;
    std::size_t values_read{};
    Parser(const Scene& s,const ClassSchema& sc,SceneStructure st,Bytes bytes)
      :scene(s),schema(sc),structure(std::move(st)),data{bytes}{
        result.pools=SceneValues::parse(s);
        result.markers=TimelineNames::parse(s).markers();
        std::size_t offset=0;
        for(auto& shape:result.pools.custom){
            shape_offsets.push_back(offset);
            if(shape.segments.size()>(std::numeric_limits<std::size_t>::max()-offset-16)/24)bad("shape offset overflow");
            offset+=16+shape.segments.size()*24;
        }
        if(auto bytes=s.section("KEYD")){
            Cursor c{*bytes};
            while(!c.done()){
                if(result.key_records.size()>=max_items)bad("KEYD limit");
                KeyframeRecord rec;rec.frame=c.packed();rec.flags=c.byte();
                switch(rec.flags&63){
                case 0:case 1:case 3:break;
                case 2:rec.extra={c.byte(),c.byte(),c.byte()};break;
                case 10:rec.extra={c.packed()};break;
                case 11:rec.extra={c.byte()};break;
                default:bad("unknown KEYD flag "+std::to_string(rec.flags));
                }
                rec.token_base=c.packed();result.key_records.push_back(std::move(rec));
            }
        }
        if(result.key_records.size()!=structure.header[9])bad("KEYD count mismatch");
    }
    std::string string(std::uint32_t i){
        if(!i)return {};
        return at(scene.strings(),i-1);
    }
    PropertyValue scalar(PropertyType type,std::uint32_t token){
        switch(type){
        case PropertyType::boolean:return token!=0;
        case PropertyType::integer:return std::bit_cast<std::int32_t>(token);
        case PropertyType::unsigned_integer:return token;
        case PropertyType::real:return at(result.pools.floats,token);
        case PropertyType::string:return string(token);
        case PropertyType::color:return ColorWord{at(result.pools.colors,token)};
        case PropertyType::vector:return at(result.pools.vectors,token);
        case PropertyType::quaternion:return at(result.pools.quaternions,token);
        case PropertyType::custom:{
            auto it=std::lower_bound(shape_offsets.begin(),shape_offsets.end(),token);
            if(it==shape_offsets.end()||*it!=token)bad("invalid CUST byte offset");
            return ShapeRef{static_cast<std::size_t>(it-shape_offsets.begin())};
        }
        case PropertyType::object:bad("compound value requires inline context");
        }
        bad("unknown property type");
    }
    PropertyValue read_value(const PropertyDefinition& prop,std::size_t depth){
        if(++values_read>max_items)bad("property value limit");
        if(prop.type==PropertyType::boolean)return scalar(prop.type,data.byte());
        auto token=data.packed();
        if(prop.type!=PropertyType::object)return scalar(prop.type,token);
        if(depth>max_depth)bad("compound nesting limit");
        auto cls=compound_class(prop.name);
        if(token<result.compounds.size()){
            if(result.compounds[token].class_name!=cls)bad("compound reference class mismatch");
            return CompoundRef{token};
        }
        CompoundProperty entry;
        entry.class_name=cls;entry.declared_count=data.packed();
        read_mask(schema.find(cls),entry.properties,depth+1);
        auto index=result.compounds.size();
        if(index>=max_items)bad("compound list limit");
        result.compounds.push_back(std::move(entry));
        return CompoundRef{index};
    }
    void read_mask(const ClassDefinition& cls,PropertyList& out,std::size_t depth){
        auto mask=data.packed();
        if(cls.properties.size()<32 && (mask>>cls.properties.size()))bad("property mask exceeds class "+cls.name);
        for(std::size_t i=0;i<cls.properties.size();++i){
            if(!(mask&(std::uint32_t(1)<<i)))continue;
            const auto& def=cls.properties[i];
            Property p{cls.name,def.name,def.type,def.indexed,{}};
            auto n=def.indexed?std::size_t(data.byte()):1;
            p.values.reserve(n);
            try{for(std::size_t j=0;j<n;++j)p.values.push_back(read_value(def,depth));}
            catch(const FormatError& e){bad(cls.name+"."+def.name+": "+e.what());}
            out.push_back(std::move(p));
        }
    }
    static void targets(const Element& node,std::string_view id,std::vector<const Element*>& found){
        for(auto& child:node.children){
            if(auto p=child.property("Id");p&&p->values.size()==1){
                if(auto s=std::get_if<std::string>(&p->values.front());s&&*s==id)found.push_back(&child);
            }
            targets(child,id,found);
        }
    }
    ElementTimeline timeline(const Element& parent){
        ElementTimeline t;t.target=string(data.packed());
        std::vector<const Element*> found;targets(parent,t.target,found);
        if(found.empty())bad("timeline target not found: "+t.target);
        if(found.size()>1)++result.statistics.ambiguous_targets;
        auto& target=*found.front();t.target_node=target.index;
        auto hierarchy=schema.hierarchy(target.class_name);
        auto n=count(data,4096);
        result.statistics.channels+=n;
        if(result.statistics.channels>max_items)bad("channel limit");
        for(std::size_t i=0;i<n;++i){
            auto descriptor=data.byte();int depth=descriptor&127;
            if(!depth)bad("empty timeline property path");
            auto cls_index=data.byte();
            if(cls_index>=hierarchy.size())bad("timeline class index");
            auto cls=hierarchy[hierarchy.size()-1-cls_index];
            Channel channel;
            for(int j=0;j<depth;++j){
                auto& p=at(cls->properties,data.byte());
                channel.path.push_back(p.name);channel.owner=cls->name;channel.type=p.type;
                if(j+1<depth){if(p.type!=PropertyType::object)bad("timeline compound path");cls=&schema.find(compound_class(p.name));}
            }
            if(descriptor&128)channel.array_index=data.packed();
            t.channels.push_back(std::move(channel));
        }
        auto nframes=count(data);auto base=data.packed();
        if(base>result.key_records.size()||nframes>result.key_records.size()-base)bad("timeline KEYD slice");
        result.statistics.keyframes+=nframes;
        if(result.statistics.keyframes>max_items)bad("keyframe limit");
        for(std::size_t i=0;i<nframes;++i){
            Keyframe k;k.metadata=result.key_records[base+i];
            auto start=k.metadata.token_base;
            if(start>structure.key_tokens.size()||n>structure.key_tokens.size()-start)bad("timeline KEYP slice");
            if(n>max_items-values_read)bad("keyframe value limit");
            values_read+=n;
            for(std::size_t j=0;j<n;++j)k.values.push_back(scalar(t.channels[j].type,structure.key_tokens[start+j]));
            t.frames.push_back(std::move(k));
        }
        ++result.statistics.timelines;
        return t;
    }
    Element node(std::size_t depth){
        if(depth>max_depth||result.statistics.nodes>=max_nodes)bad("element tree limit");
        Element e;e.index=result.statistics.nodes++;e.class_name=string(data.packed());e.flags=data.byte();
        if(e.flags&0xf0)bad("unknown element flags");
        auto hierarchy=schema.hierarchy(e.class_name);
        if((e.flags&9)==9)bad("conflicting property list flags");
        if(e.flags&1){
            auto declared=count(data,4096);PropertyList p;
            for(auto cls:hierarchy)read_mask(*cls,p,0);
            if(p.size()!=declared)bad("property count mismatch in "+e.class_name);
            result.statistics.inline_properties+=p.size();
            e.properties=std::make_shared<const PropertyList>(std::move(p));
            property_lists.push_back(e.properties);
            ++result.statistics.inline_lists;
        }else if(e.flags&8){
            e.properties=at(property_lists,data.packed());
            ++result.statistics.shared_lists;
        }else e.properties=std::make_shared<const PropertyList>();
        if(e.flags&2){
            auto n=count(data,max_nodes-result.statistics.nodes);
            if(n)++result.statistics.objects_with_children;
            e.children.reserve(n);
            for(std::size_t i=0;i<n;++i)e.children.push_back(node(depth+1));
        }
        if(e.flags&4){
            auto n=count(data);
            if(n){
                auto base=data.packed();
                if(base>result.markers.size()||n>result.markers.size()-base)bad("NAME slice");
                for(std::size_t i=0;i<n;++i)e.markers.push_back(base+i);
            }
            if(!e.children.empty()){
                auto n=count(data);
                if(n>max_items-result.statistics.timelines)bad("timeline count limit");
                for(std::size_t i=0;i<n;++i)e.timelines.push_back(timeline(e));
            }
        }
        return e;
    }
};
}
ClassSchema ClassSchema::read(std::istream& in){
    ClassSchema schema;ClassDefinition* current=nullptr;
    std::string line;std::size_t lines=0;
    while(std::getline(in,line)){
        if(++lines>100000||line.size()>4096)bad("schema size limit");
        if(line.empty()||line[0]=='#')continue;
        std::istringstream row(line);char kind;std::string name;
        if(!(row>>kind>>name))bad("malformed schema row");
        if(kind=='C'){
            std::string base;if(!(row>>base))bad("missing base class");
            if(base=="-")base.clear();
            auto [it,inserted]=schema.classes_.emplace(name,ClassDefinition{name,base,{}});
            if(!inserted)bad("duplicate schema class "+name);
            current=&it->second;
        }else if(kind=='P'){
            std::string type;int indexed;
            if(!current||!(row>>type>>indexed)||(indexed!=0&&indexed!=1))bad("malformed property row");
            if(current->properties.size()>=32)bad("class property mask limit");
            current->properties.push_back({name,type_of(type),indexed!=0});
        }else bad("unknown schema row");
        std::string trailing;if(row>>trailing)bad("trailing schema field");
    }
    if(schema.classes_.empty())bad("empty schema");
    for(auto& [name,cls]:schema.classes_)(void)schema.hierarchy(name);
    return schema;
}
const ClassDefinition& ClassSchema::find(std::string_view name)const{
    auto it=classes_.find(name);if(it==classes_.end())bad("missing schema class "+std::string(name));return it->second;
}
std::vector<const ClassDefinition*> ClassSchema::hierarchy(std::string_view name)const{
    std::vector<const ClassDefinition*> result;
    std::set<std::string_view> visited;
    while(!name.empty()){
        if(!visited.insert(name).second||result.size()>=max_depth)bad("class inheritance cycle/depth");
        auto& cls=find(name);result.push_back(&cls);name=cls.base;
    }
    std::reverse(result.begin(),result.end());return result;
}
const Property* Element::property(std::string_view name)const noexcept{
    if(properties)for(auto it=properties->rbegin();it!=properties->rend();++it)if(it->name==name)return &*it;
    return nullptr;
}
SceneTree SceneTree::parse(const Scene& scene,const ClassSchema& schema){
    auto structure=SceneStructure::parse(scene);
    if(!structure)bad("DATA tree requires XUIB v8");
    auto data=scene.section("DATA");if(!data)bad("missing DATA");
    Parser parser(scene,schema,std::move(*structure),*data);
    try{parser.result.root=parser.node(0);}
    catch(const FormatError& e){bad("DATA @"+std::to_string(parser.data.pos)+": "+e.what());}
    if(!parser.data.done())bad("unconsumed DATA bytes: "+std::to_string(data->size()-parser.data.pos));
    auto& s=parser.result.statistics;
    s.compound_lists=parser.result.compounds.size();
    if(s.nodes!=parser.structure.header[0])bad("element count mismatch");
    return std::move(parser.result);
}
}
