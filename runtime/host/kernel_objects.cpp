#include "host/kernel_objects.hpp"
#include "host/dispatcher_objects.hpp"
#include <algorithm>
#include <array>
namespace x360::host {
using abi::ImportCallResult;
namespace {
constexpr std::uint32_t invalid_handle=0xc0000008,invalid_parameter=0xc000000d,
    no_memory=0xc0000017,wrong_type=0xc0000024,semaphore_limit=0xc0000047;
std::uint32_t arg(const abi::GuestCall& s,unsigned n){return static_cast<std::uint32_t>(s.gpr[3+n]);}
ImportCallResult done(abi::GuestCall& s,std::uint32_t status){s.gpr[3]=status;return ImportCallResult::completed;}
bool output(machine::AddressSpace& m,abi::Address p,std::size_t n){
    return p&&!(p&3u)&&m.writable_range(p,n);
}
void put(std::span<std::uint8_t> bytes,unsigned i,std::uint32_t n){
    for(unsigned j=0;j<4;++j)bytes[i+j]=static_cast<std::uint8_t>(n>>(24-8*j));
}
}
KernelObjects::~KernelObjects(){
    while(!handles_.empty())close(handles_.begin()->first);
}
KernelObjects::Pointer KernelObjects::lookup(std::uint32_t handle) const{
    auto i=handles_.find(handle);return i==handles_.end()?Pointer{}:i->second;
}
std::uint32_t KernelObjects::insert(Pointer object){
    // Do not recycle handle values: a stale handle cannot silently refer to a
    // different live object. The finite title-local namespace fails closed.
    if(next_handle_>=0x7ffffffcu||handles_.size()>=16384)return 0;
    const auto h=next_handle_;next_handle_+=4;
    handles_.emplace(h,std::move(object));return h;
}
bool KernelObjects::close(std::uint32_t handle){
    auto i=handles_.find(handle);if(i==handles_.end())return false;
    if(i->second.use_count()==1&&!memory_.release(i->second->address))return false;
    handles_.erase(i);return true;
}
bool KernelObjects::handles(std::uint16_t o) noexcept{
    switch(o){case 0xce:case 0xcf:case 0xd1:case 0xd5:case 0xda:case 0xe2:
    case 0xe6:case 0xf3:case 0xf6:case 0xfd:case 0xfe:return true;default:return false;}
}
ImportCallResult KernelObjects::call(std::uint16_t o,abi::GuestCall& s,abi::GuestMemory& memory){
    if(&memory!=&memory_||!handles(o))return ImportCallResult::unsupported;
    const auto a=arg(s,0),b=arg(s,1),c=arg(s,2),d=arg(s,3);
    if(o==0xd1||o==0xd5){
        if(b)return ImportCallResult::unsupported; // named/object-attribute security not modeled
        if(!output(memory_,a,4))return ImportCallResult::fault;
        if(o==0xd1?(c>1||d>1):(!d||d>0x7fffffffu||c>d))
            return done(s,invalid_parameter);
        auto address=memory_.reserve_first(arena_begin,arena_end,4096,4096);
        if(!address)return done(s,no_memory);
        if(!memory_.commit(*address,4096,true)){memory_.release(*address);return done(s,no_memory);}
        abi::GuestCall init{};init.gpr[3]=*address;init.gpr[4]=c;init.gpr[5]=d;
        if(DispatcherObjects::call(o==0xd1?0x70:0x74,init,memory)!=ImportCallResult::completed){
            memory_.release(*address);return ImportCallResult::fault;
        }
        const auto handle=insert(std::make_shared<Object>(Object{*address,o==0xd1?Kind::event:Kind::semaphore}));
        if(!handle){memory_.release(*address);return done(s,no_memory);}
        if(!memory.store_be32(a,handle)){close(handle);return ImportCallResult::fault;}
        return done(s,0);
    }
    if(o==0xcf)return done(s,close(a)?0:invalid_handle);
    if(o==0xfe){
        const auto count=a,kind=c,mode=d,alertable=arg(s,4),timeout=arg(s,5);
        if(!count||count>64||kind>1||mode>1||alertable)return ImportCallResult::unsupported;
        if(!b||(b&3u)||std::uint64_t(b)+4*count>0x100000000ull)return ImportCallResult::fault;
        std::array<abi::Address,64> addresses{};
        for(unsigned i=0;i<count;++i){
            std::uint32_t h{};
            if(!memory.load_be32(b+4*i,h))return ImportCallResult::fault;
            auto object=lookup(h);if(!object)return done(s,invalid_handle);
            addresses[i]=object->address;
        }
        return DispatcherObjects::wait_addresses(std::span(addresses).first(count),kind,mode,alertable,timeout,s,memory);
    }
    auto object=lookup(a);
    if(!object)return done(s,invalid_handle);
    if(o==0xda){
        if(c>1)return ImportCallResult::unsupported;
        if(!output(memory_,b,4))return ImportCallResult::fault;
        const auto handle=insert(object);
        if(!handle)return done(s,no_memory);
        if(!memory.store_be32(b,handle)){close(handle);return ImportCallResult::fault;}
        if(c==1)close(a); // the new reference retains the object
        return done(s,0);
    }
    if(o==0xfd){
        abi::GuestCall wait{};wait.gpr[3]=object->address;wait.gpr[4]=3;
        wait.gpr[5]=b;wait.gpr[6]=c;wait.gpr[7]=d;
        auto result=DispatcherObjects::call(0xb0,wait,memory);
        if(result==ImportCallResult::completed)s.gpr[3]=wait.gpr[3];
        return result;
    }
    const bool semaphore=o==0xf3;
    if(object->kind!=(semaphore?Kind::semaphore:Kind::event))return done(s,wrong_type);
    if(o==0xe6){
        if(!output(memory_,b,8))return ImportCallResult::fault;
        std::array<std::uint8_t,16> body{};
        if(!memory.read(object->address,body))return ImportCallResult::fault;
        if(body[0]>1)return ImportCallResult::unsupported;
        std::uint32_t signal{};
        if(!memory.load_be32(object->address+4,signal)||signal>1)return ImportCallResult::fault;
        std::array<std::uint8_t,8> data{};put(data,0,body[0]);put(data,4,signal);
        return memory.write(b,data)?done(s,0):ImportCallResult::fault;
    }
    const auto out=o==0xce?0u:semaphore?c:b;
    if(out&&!output(memory_,out,4))return ImportCallResult::fault;
    // Returning previous state into our object body would corrupt the
    // dispatcher. Reject any overlap with the dedicated object arena.
    if(out>=arena_begin&&out<arena_end)return ImportCallResult::unsupported;
    abi::GuestCall operation{};operation.gpr[3]=object->address;
    std::uint16_t target=0;
    if(semaphore){
        std::uint32_t old{},limit{};
        if(!memory.load_be32(object->address+4,old)||!memory.load_be32(object->address+16,limit))
            return ImportCallResult::fault;
        if(!limit||old>limit)return ImportCallResult::unsupported;
        if(!b||b>limit-old)return done(s,semaphore_limit);
        operation.gpr[5]=b;target=0x88;
    }else if(o==0xce)target=0x8f;
    else if(o==0xe2)target=0x7f;
    else if(o==0xf6)target=0x9d;
    else return ImportCallResult::unsupported;
    auto result=DispatcherObjects::call(target,operation,memory);
    if(result!=ImportCallResult::completed)return result;
    if(out&&!memory.store_be32(out,static_cast<std::uint32_t>(operation.gpr[3])))return ImportCallResult::fault;
    return done(s,0);
}
}
