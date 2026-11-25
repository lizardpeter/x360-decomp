#include "formats/xui_values.hpp"
#include <bit>
#include <cmath>
#include <limits>
namespace x360::formats::xui {
namespace {
std::uint32_t word(Bytes b,std::size_t p){
    if(p>b.size()||b.size()-p<4)throw FormatError("truncated scene value");
    return (std::uint32_t(b[p])<<24)|(std::uint32_t(b[p+1])<<16)|(std::uint32_t(b[p+2])<<8)|b[p+3];
}
float real(Bytes b,std::size_t p){
    static_assert(sizeof(float)==4&&std::numeric_limits<float>::is_iec559);
    auto v=std::bit_cast<float>(word(b,p));
    if(!std::isfinite(v))throw FormatError("nonfinite scene value");
    return v;
}
template<std::size_t N> std::array<float,N> tuple(Bytes b,std::size_t p){
    std::array<float,N> out{};for(std::size_t i=0;i<N;++i)out[i]=real(b,p+4*i);return out;
}
template<std::size_t N> std::vector<std::array<float,N>> tuples(Bytes b){
    if(b.size()%(N*4))throw FormatError("unaligned scene tuple table");
    std::vector<std::array<float,N>> out;out.reserve(b.size()/(N*4));
    for(std::size_t p=0;p<b.size();p+=N*4)out.push_back(tuple<N>(b,p));
    return out;
}
}
SceneValues SceneValues::parse(const Scene& scene){
    SceneValues v;
    if(auto b=scene.section("FLOT")){
        if(b->size()%4)throw FormatError("unaligned FLOT");
        v.floats.reserve(b->size()/4);
        for(std::size_t p=0;p<b->size();p+=4)v.floats.push_back(real(*b,p));
    }
    if(auto b=scene.section("VECT"))v.vectors=tuples<3>(*b);
    if(auto b=scene.section("QUAT"))v.quaternions=tuples<4>(*b);
    if(auto b=scene.section("COLR")){
        if(b->size()%4)throw FormatError("unaligned COLR");
        for(std::size_t p=0;p<b->size();p+=4)v.colors.push_back(word(*b,p));
    }
    if(auto b=scene.section("CUST")){
        std::size_t p=0;
        while(p<b->size()){
            auto size=word(*b,p);p+=4;
            if(size<12||size>b->size()-p)throw FormatError("invalid CUST record size");
            auto record=b->subspan(p,size);p+=size;
            auto count=word(record,8);
            if((size-12)%24||count!=(size-12)/24)throw FormatError("invalid CUST segment count");
            CustomShape shape;shape.width=real(record,0);shape.height=real(record,4);
            shape.segments.reserve(count);
            for(std::size_t i=0;i<count;++i){
                auto q=12+i*24;
                shape.segments.push_back({tuple<2>(record,q),tuple<2>(record,q+8),tuple<2>(record,q+16)});
            }
            v.custom.push_back(std::move(shape));
        }
    }
    return v;
}
}
