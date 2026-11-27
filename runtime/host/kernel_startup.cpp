#include "host/kernel_startup.hpp"
#include "host/critical_sections.hpp"
#include "host/rtl_memory.hpp"
#include "host/dispatcher_objects.hpp"
#include <algorithm>
#include <set>
namespace x360::host {
using abi::ImportCallResult;
namespace {
std::uint32_t word(std::span<const std::uint8_t> b,std::size_t p){
    return (std::uint32_t(b[p])<<24)|(std::uint32_t(b[p+1])<<16)|(std::uint32_t(b[p+2])<<8)|b[p+3];
}
void put(std::span<std::uint8_t> b,std::size_t p,std::uint32_t value){
    for(unsigned i=0;i<4;++i)b[p+i]=static_cast<std::uint8_t>(value>>(24-8*i));
}
}
bool KernelStartup::install(machine::AddressSpace& memory,std::span<const std::uint8_t> header,
                           abi::Address begin,abi::Address end){
    if(ready_||header.size()<24||header.size()>0xe000||word(header,0)!=0x58455832||
       word(header,8)!=header.size()||begin>=end||(begin&3u))return false;
    const auto n=word(header,20);
    if(n>(header.size()-24)/8)return false;
    std::set<std::uint32_t> keys;
    for(std::size_t i=0;i<n;++i){
        auto key=word(header,24+8*i),offset=word(header,28+8*i);
        if(!keys.insert(key).second)return false;
        if((key&255)>1){
            if(offset>header.size()||header.size()-offset<4)return false;
            auto size=(key&255)==255?word(header,offset):4*(key&255);
            if(!size||size>header.size()-offset)return false;
        }
    }
    std::array<std::uint8_t,4> cell{};put(cell,0,loader_object);
    std::array<std::uint8_t,0x5c> object{};put(object,0x58,header_address);
    const std::array<machine::RegionMapping,3> mappings{{
        {handle_cell,cell,false},{loader_object,object,false},{header_address,header,false}}};
    if(!memory.map_batch(mappings))return false;
    header_bytes_=static_cast<std::uint32_t>(header.size());header_count_=n;
    callback_begin_=begin;callback_end_=end;ready_=true;return true;
}
bool KernelStartup::install_hardware_info(machine::AddressSpace& memory,const std::array<std::uint8_t,16>& bytes){
    if(!ready_||hardware_ready_||!bytes[4]||!memory.map(hardware_info_address,bytes,false))return false;
    hardware_ready_=true;return true;
}
std::optional<std::uint32_t> KernelStartup::value(std::string_view lib,std::uint16_t o) const{
    if(ready_&&lib=="xboxkrnl.exe"&&o==403)return handle_cell;
    if(hardware_ready_&&lib=="xboxkrnl.exe"&&o==342)return hardware_info_address;
    return {};
}
ImportCallResult KernelStartup::call(std::string_view lib,std::uint16_t o,abi::GuestCall& s,abi::GuestMemory& memory){
    if(!ready_||lib!="xboxkrnl.exe")return ImportCallResult::unsupported;
    if(files_&&(KernelFiles::handles(o)||((o==0xcf||o==0xda)&&KernelFiles::is_handle(static_cast<std::uint32_t>(s.gpr[3])))))
        return files_->call(o,s,memory);
    if(objects_&&KernelObjects::handles(o))return objects_->call(o,s,memory);
    if(pool_&&KernelPool::handles(o))return pool_->call(o,s,memory);
    if(o==204&&virtual_memory_)return virtual_memory_->allocate(s,memory);
    if(o==220&&virtual_memory_)return virtual_memory_->free(s,memory);
    if(o==225&&virtual_memory_)return virtual_memory_->protect(s,memory);
    if(o==238&&virtual_memory_)return virtual_memory_->query(s,memory);
    if(process_type_&&o==102){
        s.gpr[3]=static_cast<std::uint32_t>(*process_type_);
        return ImportCallResult::completed;
    }
    if(process_type_&&(o==302||o==303))
        return CriticalSections::initialize(s,memory,o==303);
    if(diagnostic_thread_&&(o==293||o==321))
        return CriticalSections::enter(s,memory,diagnostic_thread_,o==321);
    if(diagnostic_thread_&&o==304)
        return CriticalSections::leave(s,memory,diagnostic_thread_);
    if(o==0x11a||o==0x11b||o==0x126||o==0x12c||o==0x12d)return RtlMemory::call(o,s,memory);
    if(o==0x70||o==0x74||o==0x8f||o==0x9d||o==0x88||o==0xb0||o==0xaf||o==0x7f)return DispatcherObjects::call(o,s,memory);
    if(o==299){
        if(static_cast<abi::Address>(s.gpr[3])!=header_address)return ImportCallResult::unsupported;
        const auto key=static_cast<std::uint32_t>(s.gpr[4]);
        std::uint32_t result=0;
        for(std::uint32_t i=0;i<header_count_;++i){
            const auto at=header_address+24+8*i;std::uint32_t k{},v{};
            if(!memory.load_be32(at,k)||!memory.load_be32(at+4,v))return ImportCallResult::fault;
            if(k!=key)continue;
            if((k&255)==0)result=v;
            else if((k&255)==1)result=at+4;
            else{
                if(v>=header_bytes_)return ImportCallResult::fault;
                result=header_address+v;
            }
            break;
        }
        s.gpr[3]=result;return ImportCallResult::completed;
    }
    if(o==21){
        auto address=static_cast<abi::Address>(s.gpr[3]);
        std::array<std::uint8_t,16> record{};
        if((address&3u)||!memory.read(address,record))return ImportCallResult::fault;
        auto routine=word(record,0),priority=word(record,4);
        if((routine&3u)||routine<callback_begin_||routine>=callback_end_)return ImportCallResult::unsupported;
        if(static_cast<std::uint32_t>(s.gpr[4])){
            // Hosted registration is keyed by the original callback; repeated
            // registration updates the record. No callback execution yet.
            notifications_.insert_or_assign(routine,Notification{routine,priority});
        }else notifications_.erase(routine);
        return ImportCallResult::completed;
    }
    return ImportCallResult::unsupported;
}
}
