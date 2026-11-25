#include "os/xam/xui/image_scene.hpp"
#include <algorithm>
#include <cmath>
#include <cstdlib>
#include <iostream>
using namespace x360::os::xam::xui;
using x360::formats::png::Image;
using x360::formats::xui::FormatError;
static void require(bool b,const char* message){if(!b){std::cerr<<message<<'\n';std::exit(1);}}
int main(){
    Image texture{2,1,{255,0,0,255,0,255,0,128}};
    ImageScene s;s.canvas_width=4;s.canvas_height=2;s.width=2;s.height=1;s.x=1;s.y=1;s.scale_x=s.scale_y=1;
    auto r=render_image_scene(s,texture);
    std::vector<std::uint8_t> expected(32);
    std::copy(texture.rgba.begin(),texture.rgba.end(),expected.begin()+20);
    require(r.rgba==expected,"position and transparent background");
    s.x=0;s.y=0;s.scale_x=2;
    r=render_image_scene(s,texture);
    require(r.rgba[0]==255&&r.rgba[4]==255&&r.rgba[9]==255&&r.rgba[13]==255&&r.rgba[15]==128,"nearest sample");
    s.scale_x=1;s.x=-1;r=render_image_scene(s,texture);
    require(r.rgba[1]==255&&r.rgba[3]==128&&r.rgba[7]==0,"clip negative");
    s.x=2;s.scale_x=2;s.pivot_x=2;r=render_image_scene(s,texture);
    require(r.rgba[0]==255&&r.rgba[13]==255,"scale about pivot");
    s.scale_x=0;try{render_image_scene(s,texture);require(false,"zero scale accepted");}catch(const FormatError&){}
    s.scale_x=1;s.canvas_width=0;try{render_image_scene(s,texture);require(false,"zero canvas accepted");}catch(const FormatError&){}
    s.canvas_width=4;texture.rgba.pop_back();try{render_image_scene(s,texture);require(false,"bad source accepted");}catch(const FormatError&){}
    std::cout<<"Image scene diagnostic rendering, scaling, pivot, clipping and bounds passed\n";
}
