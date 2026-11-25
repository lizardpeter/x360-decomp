#include "formats/png.hpp"
#include <algorithm>
#include <array>
#include <cstdlib>
#include <limits>
#include <zlib.h>
namespace x360::formats::png {
namespace {
using xui::Bytes;
using xui::FormatError;
[[noreturn]] void fail(const char* s){throw FormatError(s);}
std::uint32_t word(Bytes b,std::size_t p){
    if(p>b.size()||b.size()-p<4)fail("truncated PNG word");
    return (std::uint32_t(b[p])<<24)|(std::uint32_t(b[p+1])<<16)|(std::uint32_t(b[p+2])<<8)|b[p+3];
}
int paeth(int a,int b,int c){
    int p=a+b-c,pa=std::abs(p-a),pb=std::abs(p-b),pc=std::abs(p-c);
    return pa<=pb&&pa<=pc?a:pb<=pc?b:c;
}
constexpr std::size_t max_bytes=64u*1024*1024;
}
Image decode(Bytes data){
    constexpr std::array<std::uint8_t,8> signature{137,80,78,71,13,10,26,10};
    if(data.size()<8||!std::equal(signature.begin(),signature.end(),data.begin()))fail("bad PNG signature");
    Image result;unsigned depth=0,color=0,channels=0;
    bool header=false,ended=false,saw_idat=false,closed_idat=false,has_palette=false,has_alpha=false;
    std::vector<std::uint8_t> compressed,palette,alpha;
    std::size_t p=8;
    while(p<data.size()){
        if(data.size()-p<12)fail("truncated PNG chunk");
        auto size=word(data,p);
        if(size>data.size()-p-12||size>max_bytes)fail("invalid PNG chunk length");
        auto t=data.subspan(p+4,4),payload=data.subspan(p+8,size);
        std::string_view tag(reinterpret_cast<const char*>(t.data()),4);
        if(!std::all_of(t.begin(),t.end(),[](auto c){return (c>='A'&&c<='Z')||(c>='a'&&c<='z');})||(t[2]&32))fail("invalid PNG chunk name");
        auto crc=crc32(0,Z_NULL,0);
        crc=crc32(crc,t.data(),4);crc=crc32(crc,payload.data(),static_cast<uInt>(size));
        if(crc!=word(data,p+8+size))fail("PNG CRC mismatch");
        p+=12+size;
        if(!header&&tag!="IHDR")fail("missing first PNG header");
        if(saw_idat&&tag!="IDAT")closed_idat=true;
        if(tag=="IHDR"){
            if(header||size!=13)fail("invalid PNG IHDR");
            result.width=word(payload,0);result.height=word(payload,4);depth=payload[8];color=payload[9];
            if(!result.width||!result.height||std::uint64_t(result.width)*result.height>max_bytes/4)
                fail("PNG dimensions exceed budget");
            if(payload[10]||payload[11]||payload[12])fail("unsupported PNG compression/filter/interlace");
            switch(color){
                case 0:channels=1;break;case 2:channels=3;break;case 3:channels=1;break;
                case 4:channels=2;break;case 6:channels=4;break;default:fail("unsupported PNG color type");
            }
            if(depth!=8&&!(color==3&&(depth==1||depth==2||depth==4)))fail("unsupported PNG sample depth");
            header=true;
        }else if(tag=="PLTE"){
            if(has_palette||saw_idat||has_alpha||!size||size%3||size>768||color==0||color==4)
                fail("invalid PNG palette");
            if(color==3&&size/3>(1u<<depth))fail("PNG palette exceeds index range");
            palette.assign(payload.begin(),payload.end());has_palette=true;
        }else if(tag=="tRNS"){
            if(has_alpha||saw_idat||color!=3||!has_palette||!size||size>palette.size()/3)
                fail("unsupported PNG transparency");
            alpha.assign(payload.begin(),payload.end());has_alpha=true;
        }else if(tag=="IDAT"){
            if(closed_idat||(color==3&&!has_palette)||size>max_bytes-compressed.size())fail("invalid PNG IDAT");
            compressed.insert(compressed.end(),payload.begin(),payload.end());saw_idat=true;
        }else if(tag=="IEND"){
            if(size||!saw_idat||p!=data.size())fail("invalid PNG IEND");
            ended=true;break;
        }else if(!(t[0]&32))fail("unsupported critical PNG chunk");
    }
    if(!ended||compressed.empty())fail("incomplete PNG");
    const std::uint64_t row64=(std::uint64_t(result.width)*channels*depth+7)/8;
    const auto raw64=(row64+1)*result.height;
    if(raw64>=max_bytes)fail("PNG scanlines exceed budget");
    std::size_t row=static_cast<std::size_t>(row64);
    // Allocate an extra byte to reject an overlong decompressed stream.
    std::vector<std::uint8_t> raw(static_cast<std::size_t>(raw64)+1);
    z_stream z{};
    z.next_in=compressed.data();z.avail_in=static_cast<uInt>(compressed.size());
    z.next_out=raw.data();z.avail_out=static_cast<uInt>(raw.size());
    if(inflateInit(&z)!=Z_OK)fail("PNG inflate initialization failed");
    auto code=inflate(&z,Z_FINISH);auto produced=z.total_out;auto remaining=z.avail_in;
    inflateEnd(&z);
    if(code!=Z_STREAM_END||produced!=raw64||remaining)fail("PNG deflate length mismatch");
    unsigned bpp=std::max(1u,(channels*depth+7)/8);
    std::vector<std::uint8_t> prev(row),current(row);
    result.rgba.reserve(std::size_t(result.width)*result.height*4);
    for(std::size_t y=0;y<result.height;++y){
        auto line=raw.data()+y*(row+1);
        unsigned filter=line[0];if(filter>4)fail("invalid PNG filter");
        for(std::size_t i=0;i<row;++i){
            int a=i>=bpp?current[i-bpp]:0,b=prev[i],c=i>=bpp?prev[i-bpp]:0;
            int prediction=filter==0?0:filter==1?a:filter==2?b:filter==3?(a+b)/2:paeth(a,b,c);
            current[i]=static_cast<std::uint8_t>(line[i+1]+prediction);
        }
        for(std::size_t x=0;x<result.width;++x){
            std::array<std::uint8_t,4> pixel{};
            if(color==3){
                auto bit=x*depth;auto idx=(current[bit/8]>>(8-depth-bit%8))&((1u<<depth)-1);
                if(idx>=palette.size()/3)fail("PNG palette index out of bounds");
                pixel={palette[idx*3],palette[idx*3+1],palette[idx*3+2],idx<alpha.size()?alpha[idx]:std::uint8_t{255}};
            }else{
                auto at=x*channels;auto v=current[at];
                switch(color){
                    case 0:pixel={v,v,v,255};break;
                    case 2:pixel={v,current[at+1],current[at+2],255};break;
                    case 4:pixel={v,v,v,current[at+1]};break;
                    case 6:pixel={v,current[at+1],current[at+2],current[at+3]};break;
                }
            }
            result.rgba.insert(result.rgba.end(),pixel.begin(),pixel.end());
        }
        prev.swap(current);
    }
    return result;
}
}
