#include "formats/xui_mounts.hpp"
#include <cstdlib>
#include <iostream>
using namespace x360::formats::xui;
using V=std::vector<std::uint8_t>;
static void check(bool b,const char* why){if(!b){std::cerr<<why<<'\n';std::exit(1);}}
static void u32(V& b,std::uint32_t n){for(int i=24;i>=0;i-=8)b.push_back(std::uint8_t(n>>i));}
static V archive(bool conflict){
    const std::vector<std::string> keys{"Image.PNG","image.png","..\\handles\\clip.xma"};
    V dir,contents;
    for(std::size_t i=0;i<keys.size();++i){
        u32(dir,1);u32(dir,contents.size());dir.push_back(std::uint8_t(keys[i].size()));
        dir.insert(dir.end(),keys[i].begin(),keys[i].end());contents.push_back(i==1&&conflict?9:7);
    }
    V b{'X','U','I','Z'};u32(b,3);u32(b,22+dir.size()+contents.size());u32(b,0);u32(b,dir.size());
    b.push_back(0);b.push_back(keys.size());b.insert(b.end(),dir.begin(),dir.end());b.insert(b.end(),contents.begin(),contents.end());return b;
}
int main(){
    auto bytes=archive(false),other=archive(true);
    auto a=Archive::parse(bytes),b=Archive::parse(other);
    Mounts m;m.mount("common",a);m.mount("controlpack",b);
    check(m.resolve("common://Image.PNG").state==ResolveState::exact,"exact");
    check(m.resolve("common://IMAGE.PNG").state==ResolveState::normalized,"case fold");
    auto r=m.resolve("common://../handles/clip.xma");
    check(r.state==ResolveState::normalized&&r.data.size()==1&&r.data[0]==7,"literal slash folding");
    check(m.resolve("common://handles/clip.xma").state==ResolveState::missing,"must not collapse segments");
    check(m.resolve("controlpack://Image.PNG").state==ResolveState::ambiguous,"conflict");
    check(m.resolve("file://anything").state==ResolveState::unsupported_scheme,"host file rejected");
    check(m.resolve("https://example.test").state==ResolveState::unsupported_scheme,"network rejected");
    check(m.resolve("common://").state==ResolveState::malformed,"empty path");
    check(m.resolve("common:Image.PNG").state==ResolveState::malformed,"malformed URI");
    try{m.mount("file",a);check(false,"external mount accepted");}catch(const FormatError&){}
    std::cout<<"XUI mount resolution, literal virtual paths and conflict tests passed\n";
}
