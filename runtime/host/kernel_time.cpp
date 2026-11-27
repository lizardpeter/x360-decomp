#include "host/kernel_time.hpp"
#include <array>
#include <limits>
namespace x360::host {
using abi::ImportCallResult;
using namespace std::chrono;
namespace {
constexpr sys_days epoch=year{1601}/January/1;
constexpr sys_days limit=year{10000}/January/1;
constexpr std::uint64_t per_day=864000000000ull;
constexpr std::uint64_t max_ticks=static_cast<std::uint64_t>((limit-epoch).count())*per_day-1;
constexpr std::uint64_t unix_bias=116444736000000000ull;
using HundredNs=duration<std::int64_t,std::ratio<1,10000000>>;
std::uint32_t arg(const abi::GuestCall& s,unsigned i){return static_cast<std::uint32_t>(s.gpr[3+i]);}
ImportCallResult done(abi::GuestCall& s,std::uint64_t value){s.gpr[3]=value;return ImportCallResult::completed;}
bool load64(const abi::GuestMemory& m,abi::Address p,std::uint64_t& n){
    std::array<std::uint8_t,8> bytes{};if(!p||(p&7u)||!m.read(p,bytes))return false;
    n=0;for(auto b:bytes)n=(n<<8)|b;return true;
}
bool store64(abi::GuestMemory& m,abi::Address p,std::uint64_t n){
    std::array<std::uint8_t,8> bytes{};for(unsigned j=0;j<8;++j)bytes[j]=static_cast<std::uint8_t>(n>>(56-8*j));
    return p&&!(p&7u)&&m.write(p,bytes);
}
}
KernelTime::Sample KernelTime::now() const noexcept{
    if(sample_)return *sample_;
    const auto unix=duration_cast<HundredNs>(system_clock::now().time_since_epoch()).count();
    const auto elapsed=duration_cast<HundredNs>(steady_clock::now()-start_).count();
    const auto system=unix< -static_cast<std::int64_t>(unix_bias)?0ull:
        static_cast<std::uint64_t>(unix+static_cast<std::int64_t>(unix_bias));
    return {system,static_cast<std::uint64_t>(elapsed<0?0:elapsed)};
}
bool KernelTime::handles(std::uint16_t o) noexcept{return o==0x82||o==0x83||o==0x84||o==0x13f||o==0x140;}
ImportCallResult KernelTime::call(std::uint16_t o,abi::GuestCall& s,abi::GuestMemory& m) const{
    const auto a=arg(s,0),b=arg(s,1);
    if(o==0x82)return done(s,now().uptime);
    if(o==0x83)return done(s,frequency);
    if(o==0x84)return !a||store64(m,a,now().system)?ImportCallResult::completed:ImportCallResult::fault;
    if(o==0x13f){
        if(!a||(a&1u))return ImportCallResult::fault;
        std::array<std::uint8_t,16> bytes{};if(!m.read(a,bytes))return ImportCallResult::fault;
        std::array<unsigned,8> v{};for(unsigned i=0;i<v.size();++i)v[i]=(unsigned(bytes[2*i])<<8)|bytes[2*i+1];
        if(v[0]<1601||v[0]>9999||v[1]<1||v[1]>12||v[2]<1||v[2]>31||
           v[3]>23||v[4]>59||v[5]>59||v[6]>999)return done(s,0);
        const year_month_day date{year{static_cast<int>(v[0])},month{v[1]},day{v[2]}};
        if(!date.ok())return done(s,0);
        const auto days_since=(sys_days(date)-epoch).count();
        const auto ticks=static_cast<std::uint64_t>(days_since)*per_day+
            (std::uint64_t(v[3])*3600+std::uint64_t(v[4])*60+v[5])*frequency+v[6]*10000ull;
        return store64(m,b,ticks)?done(s,1):ImportCallResult::fault;
    }
    if(o==0x140){
        std::uint64_t ticks{};if(!load64(m,a,ticks)||!b||(b&1u))return ImportCallResult::fault;
        if(ticks>max_ticks)return ImportCallResult::unsupported;
        const auto date=epoch+days{static_cast<days::rep>(ticks/per_day)};
        const year_month_day ymd{date};
        auto ms=(ticks%per_day)/10000;
        const std::array<unsigned,8> v{static_cast<unsigned>(int(ymd.year())),unsigned(ymd.month()),unsigned(ymd.day()),
            unsigned(ms/3600000),unsigned(ms/60000%60),unsigned(ms/1000%60),unsigned(ms%1000),weekday{date}.c_encoding()};
        std::array<std::uint8_t,16> bytes{};
        for(unsigned i=0;i<v.size();++i){bytes[2*i]=static_cast<std::uint8_t>(v[i]>>8);bytes[2*i+1]=static_cast<std::uint8_t>(v[i]);}
        return m.write(b,bytes)?ImportCallResult::completed:ImportCallResult::fault;
    }
    return ImportCallResult::unsupported;
}
}
