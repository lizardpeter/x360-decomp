#include "os/xam/xui/image_scene.hpp"
#include "formats/xui_values.hpp"
#include "formats/xui_structure.hpp"
#include <algorithm>
#include <cmath>
namespace x360::os::xam::xui {
namespace {
using formats::xui::FormatError;
using formats::xui::Bytes;
constexpr std::uint64_t pixel_budget=16u*1024u*1024u;
template<std::size_t N>bool matches(Bytes b,const std::array<std::uint8_t,N>& pattern){
    return b.size()==N&&std::equal(b.begin(),b.end(),pattern.begin());
}
bool bounded(double v){return std::isfinite(v)&&std::abs(v)<=1000000.;}
std::uint32_t dimension(float n){
    if(!std::isfinite(n)||n<1||n>8192||std::floor(n)!=n)throw FormatError("unsupported canvas dimension");
    return static_cast<std::uint32_t>(n);
}
}
std::optional<ImageScene> parse_image_scene(const formats::xui::Scene& scene){
    if(scene.version()!=8||scene.strings().size()!=6)return {};
    const auto& strings=scene.strings();
    if(strings[3]!="XuiImage"||strings[4]!="XuiScene"||strings[5]!="XuiCanvas")return {};
    auto data=scene.section("DATA");if(!data)return {};
    // Three serialized node records. The two observed masks differ by the
    // optional origin/pivot vector. The property-index interpretation is
    // confined to this exact layout, not generalized to unknown node types.
    constexpr std::array<std::uint8_t,29> plain{
        6,3,2,6,0,1,0,1,5,3,3,7,1,0,1,0,0,1,4,1,6,31,2,2,3,0,1,2,3};
    constexpr std::array<std::uint8_t,31> pivot{
        6,3,2,6,0,1,0,1,5,3,3,7,1,0,1,0,0,1,4,1,7,241,31,2,2,3,0,1,2,2,3};
    bool has_pivot=matches(*data,pivot);
    if(!has_pivot&&!matches(*data,plain))return {};
    auto structure=formats::xui::SceneStructure::parse(scene);
    if(!structure||structure->header[0]!=3||structure->header[2]!=3||
       structure->header[11]!=2||structure->header[1]!=(has_pivot?12:11)||
       structure->key_token_count()||structure->name_record_count())throw FormatError("image scene structure mismatch");
    auto v=formats::xui::SceneValues::parse(scene);
    if(v.floats.size()!=4||v.vectors.size()!=(has_pivot?3:2)||!v.quaternions.empty()||
       !v.colors.empty()||!v.custom.empty())throw FormatError("image scene value mismatch");
    ImageScene s;
    s.scene_id=strings[0];s.image_id=strings[1];s.texture_uri=strings[2];
    s.canvas_width=dimension(v.floats[0]);s.canvas_height=dimension(v.floats[1]);
    s.width=v.floats[2];s.height=v.floats[3];
    s.x=v.vectors[0][0];s.y=v.vectors[0][1];s.scale_x=v.vectors[1][0];s.scale_y=v.vectors[1][1];
    if(has_pivot){s.pivot_x=v.vectors[2][0];s.pivot_y=v.vectors[2][1];}
    if(s.texture_uri.empty()||v.vectors[0][2]!=0.f||(has_pivot&&v.vectors[2][2]!=0.f))throw FormatError("unsupported image scene vector");
    return s;
}
formats::png::Image render_image_scene(const ImageScene& s,const formats::png::Image& texture){
    auto pixels=std::uint64_t(s.canvas_width)*s.canvas_height;
    auto src_pixels=std::uint64_t(texture.width)*texture.height;
    if(!pixels||pixels>pixel_budget||!src_pixels||src_pixels>pixel_budget||texture.rgba.size()!=src_pixels*4)
        throw FormatError("invalid diagnostic texture/canvas");
    for(double v:{s.x,s.y,s.width,s.height,s.scale_x,s.scale_y,s.pivot_x,s.pivot_y})
        if(!bounded(v))throw FormatError("nonfinite or unbounded image transform");
    if(s.width<=0||s.height<=0||s.scale_x<=0||s.scale_y<=0)
        throw FormatError("unsupported image extent or scale");
    const double left=s.x+s.pivot_x*(1-s.scale_x),top=s.y+s.pivot_y*(1-s.scale_y);
    const double width=s.width*s.scale_x,height=s.height*s.scale_y;
    formats::png::Image image{s.canvas_width,s.canvas_height,{}};
    image.rgba.resize(static_cast<std::size_t>(pixels)*4,0);
    for(std::uint32_t y=0;y<s.canvas_height;++y){
        const double v=(y+0.5-top)/height;
        if(!(v>=0&&v<1))continue;
        auto sy=std::min(texture.height-1,static_cast<std::uint32_t>(v*texture.height));
        for(std::uint32_t x=0;x<s.canvas_width;++x){
            const double u=(x+0.5-left)/width;
            if(!(u>=0&&u<1))continue;
            auto sx=std::min(texture.width-1,static_cast<std::uint32_t>(u*texture.width));
            auto i=(std::size_t(sy)*texture.width+sx)*4;
            auto j=(std::size_t(y)*s.canvas_width+x)*4;
            std::copy_n(texture.rgba.data()+i,4,image.rgba.data()+j);
        }
    }
    return image;
}
}
