#include "os/xam/xui/geometry.hpp"
#include <algorithm>
#include <cmath>
#include <stdexcept>
namespace x360::os::xam::xui {
namespace {
Vec2 mid(Vec2 a,Vec2 b){return {a[0]*0.5f+b[0]*0.5f,a[1]*0.5f+b[1]*0.5f};}
bool finite(Vec2 a){return std::isfinite(a[0])&&std::isfinite(a[1]);}
double distance(Vec2 p,Vec2 a,Vec2 b){
    const double dx=double(b[0])-a[0],dy=double(b[1])-a[1];
    const double x=double(p[0])-a[0],y=double(p[1])-a[1];
    const double len=dx*dx+dy*dy;
    const double t=len?std::clamp((x*dx+y*dy)/len,0.0,1.0):0.0;
    return std::hypot(x-dx*t,y-dy*t);
}
void flatten(Vec2 p0,Vec2 p1,Vec2 p2,Vec2 p3,double tolerance,unsigned depth,std::vector<Vec2>& out){
    if(distance(p1,p0,p3)<=tolerance&&distance(p2,p0,p3)<=tolerance){
        if(out.back()!=p3)out.push_back(p3);return;
    }
    if(!depth)throw std::runtime_error("CUST tessellation tolerance not met");
    auto a=mid(p0,p1),b=mid(p1,p2),c=mid(p2,p3),d=mid(a,b),e=mid(b,c),f=mid(d,e);
    flatten(p0,a,d,f,tolerance,depth-1,out);
    flatten(f,e,c,p3,tolerance,depth-1,out);
}
}
std::vector<Vec2> flatten_closed_shape(const formats::xui::CustomShape& shape,float tolerance,unsigned max_depth){
    if(!std::isfinite(tolerance)||tolerance<=0||max_depth>16)
        throw std::invalid_argument("invalid path tolerance/depth");
    if(shape.segments.empty())return {};
    // The prior endpoint for the first segment is the final endpoint of the
    // closed contour, including original one-segment degenerate records.
    auto start=shape.segments.back().end;
    if(!finite(start))throw std::invalid_argument("nonfinite path");
    std::vector<Vec2> out{start};
    auto from=start;
    for(auto& s:shape.segments){
        if(!finite(s.control1)||!finite(s.control2)||!finite(s.end))
            throw std::invalid_argument("nonfinite path");
        flatten(from,s.control1,s.control2,s.end,tolerance,max_depth,out);
        from=s.end;
    }
    return out;
}
}
