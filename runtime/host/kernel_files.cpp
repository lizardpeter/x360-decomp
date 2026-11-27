#include "host/kernel_files.hpp"
#include <algorithm>
#include <array>
#include <fstream>
#include <limits>
#include <optional>
#include <set>
#include <system_error>
namespace x360::host {
using abi::ImportCallResult;
namespace {
constexpr std::uint32_t success=0,invalid_handle=0xc0000008,invalid_parameter=0xc000000d,
    length_mismatch=0xc0000004,access_denied=0xc0000022,invalid_name=0xc0000033,
    name_not_found=0xc0000034,no_memory=0xc0000017,eof=0xc0000011,
    no_more_files=0x80000006,no_such_file=0xc000000f,buffer_overflow=0x80000005,
    not_directory=0xc0000103,is_directory=0xc00000ba,invalid_class=0xc0000003;
constexpr std::uint32_t max_io=16u*1024*1024;
std::uint32_t arg(const abi::GuestCall& s,unsigned n){return static_cast<std::uint32_t>(s.gpr[3+n]);}
ImportCallResult done(abi::GuestCall& s,std::uint32_t n){s.gpr[3]=n;return ImportCallResult::completed;}
bool writable(machine::AddressSpace& m,abi::Address p,std::size_t n){return p&&m.writable_range(p,n);}
bool overlap(abi::Address a,std::size_t n,abi::Address b,std::size_t m){
    return n&&m&&std::uint64_t(a)<std::uint64_t(b)+m&&std::uint64_t(b)<std::uint64_t(a)+n;
}
void put(std::span<std::uint8_t> b,unsigned i,std::uint64_t value,unsigned count=4){
    for(unsigned j=0;j<count;++j)b[i+j]=static_cast<std::uint8_t>(value>>(8*(count-1-j)));
}
bool iosb(machine::AddressSpace& m,abi::Address at,std::uint32_t status,std::uint32_t info){
    if(!at)return true;
    std::array<std::uint8_t,8> b{};put(b,0,status);put(b,4,info);return m.write(at,b);
}
bool load64(const abi::GuestMemory& m,abi::Address a,std::uint64_t& n){
    std::array<std::uint8_t,8> b{};if(!m.read(a,b))return false;
    n=0;for(auto x:b)n=(n<<8)|x;return true;
}
char lower(char c){return c>='A'&&c<='Z'?static_cast<char>(c+32):c;}
std::string folded(std::string s){for(auto& c:s)c=lower(c);return s;}
std::optional<std::string> normalize(std::string s){
    if(s.empty()||s.size()>1024)return {};
    for(auto& c:s){if(c=='\\')c='/';if(static_cast<unsigned char>(c)<32||static_cast<unsigned char>(c)>126)return {};}
    if(s.starts_with("/??/"))s.erase(0,4);
    auto l=folded(s);
    if(l=="/device/flash")s="flash:";
    else if(l.starts_with("/device/flash/"))s="flash:/"+s.substr(14);
    auto colon=s.find(':');
    if(colon==std::string::npos||colon==0||colon>32)return {};
    for(char c:s.substr(0,colon))if(!(lower(c)>='a'&&lower(c)<='z')&&!(c>='0'&&c<='9')&&c!='_')return {};
    if(colon+1<s.size()&&s[colon+1]!='/')return {};
    std::string out=folded(s.substr(0,colon+1));
    std::size_t start=colon+1;
    while(start<s.size()){
        if(s[start++]!='/')return {};
        auto end=s.find('/',start);if(end==std::string::npos)end=s.size();
        auto part=s.substr(start,end-start);
        if(part.empty()){if(end!=s.size())return {};break;}
        if(part=="."||part==".."||part.size()>255||part.back()=='.'||part.back()==' '||
           part.find_first_of(":*?\"<>|")!=std::string::npos)return {};
        out+="/"+folded(part);start=end;
    }
    return out;
}
std::string basename(std::string_view s){
    auto i=s.find_last_of("/\\");return std::string(i==std::string::npos?s:s.substr(i+1));
}
std::string parent(std::string_view s){
    auto i=s.find_last_of('/');return i==std::string::npos?std::string{}:std::string(s.substr(0,i));
}
bool ascii(const abi::GuestMemory& m,abi::Address at,std::string& out){
    if(!at){out.clear();return true;}
    std::uint32_t lens{},ptr{};
    if((at&3u)||!m.load_be32(at,lens)||at>0xfffffff8u||!m.load_be32(at+4,ptr))return false;
    const auto length=lens>>16,capacity=lens&0xffff;
    if(length>capacity||length>1024||(!ptr&&length))return false;
    std::vector<std::uint8_t> b(length);
    if(length&&!m.read(ptr,b))return false;
    out.assign(b.begin(),b.end());
    return out.find('\0')==std::string::npos;
}
bool match(std::string_view pattern,std::string_view name){
    // Standard bounded wildcard match, with case-insensitive ASCII.
    std::size_t p=0,n=0,star=std::string::npos,retry=0;
    while(n<name.size()){
        if(p<pattern.size()&&(pattern[p]=='?'||lower(pattern[p])==lower(name[n]))){++p;++n;}
        else if(p<pattern.size()&&pattern[p]=='*'){star=p++;retry=n;}
        else if(star!=std::string::npos){p=star+1;n=++retry;}
        else return false;
    }
    while(p<pattern.size()&&pattern[p]=='*')++p;
    return p==pattern.size();
}
std::uint64_t index_of(std::string_view p){
    std::uint64_t n=14695981039346656037ull;for(unsigned char c:p)n=(n^c)*1099511628211ull;return n;
}
}
bool KernelFiles::add(std::string_view input,bool directory,std::span<const std::uint8_t> bytes){
    auto key=normalize(std::string(input));if(!key||(!directory&&key->find('/')==std::string::npos)||
       bytes.size()>budget-total_bytes_)return false;
    auto existing=nodes_.find(*key);
    if(existing!=nodes_.end())return directory&&existing->second.directory;
    std::vector<std::string> parents;
    for(auto p=parent(*key);!p.empty();p=parent(p)){
        auto it=nodes_.find(p);
        if(it!=nodes_.end()){if(!it->second.directory)return false;break;}
        parents.push_back(p);
    }
    for(auto i=parents.rbegin();i!=parents.rend();++i)nodes_.emplace(*i,Node{basename(*i),true,{}});
    nodes_.emplace(*key,Node{basename(input),directory,{bytes.begin(),bytes.end()}});
    total_bytes_+=bytes.size();return true;
}
bool KernelFiles::add_file(std::string_view path,std::span<const std::uint8_t> bytes){return add(path,false,bytes);}
bool KernelFiles::add_directory(std::string_view path){return add(path,true,{});}
bool KernelFiles::mount(std::string_view volume,const std::filesystem::path& root){
    namespace fs=std::filesystem;
    auto key=normalize(std::string(volume));if(!key||key->find('/')!=std::string::npos||nodes_.contains(*key))return false;
    std::error_code ec;
    auto root_status=fs::symlink_status(root,ec);if(ec||fs::is_symlink(root_status)||!fs::is_directory(root_status))return false;
    KernelFiles staged(memory_);
    if(!staged.add_directory(*key))return false;
    std::set<std::string> encountered;
    for(fs::recursive_directory_iterator it(root,ec),end;it!=end&&!ec;it.increment(ec)){
        auto stat=it->symlink_status(ec);if(ec||fs::is_symlink(stat))return false;
        auto relative=it->path().lexically_relative(root).generic_string();
        auto path=*key+"/"+relative;
        auto canonical=normalize(path);
        if(!canonical||!encountered.insert(*canonical).second)return false;
        if(fs::is_directory(stat)){
            if(!staged.add_directory(path))return false;
        }else if(fs::is_regular_file(stat)){
            auto n=it->file_size(ec);if(ec||n>budget-total_bytes_-staged.total_bytes_)return false;
            std::vector<std::uint8_t> data(static_cast<std::size_t>(n));
            std::ifstream in(it->path(),std::ios::binary);
            if(!in||(n&&!in.read(reinterpret_cast<char*>(data.data()),static_cast<std::streamsize>(n)))||
                in.peek()!=std::char_traits<char>::eof())return false;
            if(!staged.add_file(path,data))return false;
        }else return false;
    }
    if(ec)return false;
    // Only a trusted, locally staged tree is accepted. No host file handles
    // or paths survive this snapshot; later guest operations use these bytes.
    total_bytes_+=staged.total_bytes_;nodes_.merge(staged.nodes_);return true;
}
std::pair<std::uint32_t,std::string> KernelFiles::object_path(abi::Address attrs) const{
    if(!attrs||(attrs&3u)||attrs>0xfffffff4u)return {invalid_parameter,{}};
    std::uint32_t root{},name{},flags{};
    if(!memory_.load_be32(attrs,root)||!memory_.load_be32(attrs+4,name)||!memory_.load_be32(attrs+8,flags))
        return {invalid_parameter,{}};
    if(flags&~0xc0u)return {invalid_parameter,{}};
    std::string path;if(!name||!ascii(memory_,name,path))return {invalid_name,{}};
    if(root&&root!=0xfffffffdu){
        auto it=open_.find(root);if(it==open_.end())return {invalid_handle,{}};
        if(!nodes_.at(it->second->path).directory)return {not_directory,{}};
        if(path.empty()||path.front()=='/'||path.front()=='\\'||path.find(':')!=std::string::npos)return {invalid_name,{}};
        path=it->second->path+"/"+path;
    }
    auto normal=normalize(path);if(!normal)return {invalid_name,{}};
    return {success,*normal};
}
std::uint32_t KernelFiles::insert(std::shared_ptr<Open> object){
    if(open_.size()>=16384||next_>=0x4ffffffcu)return 0;
    auto h=next_;next_+=4;open_.emplace(h,std::move(object));return h;
}
bool KernelFiles::handles(std::uint16_t o) noexcept{
    switch(o){case 0xd2:case 0xdb:case 0xdf:case 0xe4:case 0xe7:case 0xe8:case 0xf0:case 0xf7:case 0xff:return true;default:return false;}
}
ImportCallResult KernelFiles::call(std::uint16_t o,abi::GuestCall& s,abi::GuestMemory& memory){
    if(&memory!=&memory_)return ImportCallResult::unsupported;
    auto a=arg(s,0),b=arg(s,1),c=arg(s,2),d=arg(s,3),e=arg(s,4);
    if(o==0xd2||o==0xdf){
        auto disposition=o==0xdf?1u:arg(s,7),options=o==0xdf?e:arg(s,8);
        if(!writable(memory_,a,4)||(d&&!writable(memory_,d,8))||overlap(a,4,d,d?8:0))return ImportCallResult::fault;
        auto [status,path]=object_path(c);
        if(status)return done(s,status);
        if(b&0x500d0116u)return done(s,access_denied); // mutating access, delete, generic write/all
        if(disposition!=1&&disposition!=3)return done(s,access_denied);
        if(options&~0x7fu||((options&1)&&(options&0x40)))return ImportCallResult::unsupported;
        auto node=nodes_.find(path);
        if(node==nodes_.end())return done(s,disposition==3?access_denied:name_not_found);
        if((options&1)&&!node->second.directory)return done(s,not_directory);
        if((options&0x40)&&node->second.directory)return done(s,is_directory);
        auto h=insert(std::make_shared<Open>(Open{path,0,(b&0x80000001u)!=0,{},0,false}));
        if(!h)return done(s,no_memory);
        if(!memory.store_be32(a,h)||!iosb(memory_,d,0,1)){open_.erase(h);return ImportCallResult::fault;}
        return done(s,0);
    }
    if(o==0xe7){
        if(!writable(memory_,b,56))return ImportCallResult::fault;
        auto [status,path]=object_path(a);if(status)return done(s,status);
        auto i=nodes_.find(path);if(i==nodes_.end())return done(s,name_not_found);
        std::array<std::uint8_t,56> info{};
        put(info,32,i->second.bytes.size(),8);put(info,40,i->second.bytes.size(),8);
        put(info,48,i->second.directory?0x10:0x1);
        return memory.write(b,info)?done(s,0):ImportCallResult::fault;
    }
    auto it=open_.find(a);if(it==open_.end())return done(s,invalid_handle);
    auto& file=*it->second;const auto& node=nodes_.at(file.path);
    if(o==0xcf){open_.erase(it);return done(s,0);}
    if(o==0xda){
        if(c>1)return ImportCallResult::unsupported;
        if(!writable(memory_,b,4))return ImportCallResult::fault;
        auto h=insert(it->second);if(!h)return done(s,no_memory);
        if(!memory.store_be32(b,h)){open_.erase(h);return ImportCallResult::fault;}
        if(c==1)open_.erase(a);
        return done(s,0);
    }
    if(o==0xff)return done(s,access_denied);
    if(o==0xdb){
        if(b&&!writable(memory_,b,8))return ImportCallResult::fault;
        return iosb(memory_,b,0,0)?done(s,0):ImportCallResult::fault;
    }
    if(o==0xf0){
        if(b||c||d)return ImportCallResult::unsupported;
        if(node.directory)return done(s,is_directory);
        if(!file.readable)return done(s,access_denied);
        auto buffer=arg(s,5),length=arg(s,6),offset=arg(s,7);
        if(length>max_io)return ImportCallResult::unsupported;
        if(e&&!writable(memory_,e,8))return ImportCallResult::fault;
        std::uint64_t pos=file.position;
        if(offset){
            if((offset&7u)||!load64(memory,offset,pos))return ImportCallResult::fault;
            if(pos==~std::uint64_t{0})pos=file.position;
            else if(pos>std::numeric_limits<std::int64_t>::max())return done(s,invalid_parameter);
        }
        if(!length)return iosb(memory_,e,0,0)?done(s,0):ImportCallResult::fault;
        if(pos>=node.bytes.size())return done(s,eof);
        auto n=static_cast<std::uint32_t>(std::min<std::uint64_t>(length,node.bytes.size()-pos));
        if(!writable(memory_,buffer,n)||overlap(buffer,n,e,e?8:0))return ImportCallResult::fault;
        if(!memory.write(buffer,std::span(node.bytes).subspan(static_cast<std::size_t>(pos),n))||
           !iosb(memory_,e,0,n))return ImportCallResult::fault;
        file.position=pos+n;return done(s,0);
    }
    if(o==0xe8||o==0xf7){
        if(b&&!writable(memory_,b,8))return ImportCallResult::fault;
        if(o==0xf7){
            if(e!=14)return done(s,access_denied);
            if(d<8)return done(s,length_mismatch);
            std::uint64_t pos{};if(!load64(memory,c,pos))return ImportCallResult::fault;
            if(pos>std::numeric_limits<std::int64_t>::max())return done(s,invalid_parameter);
            if(!iosb(memory_,b,0,8))return ImportCallResult::fault;
            file.position=pos;return done(s,0);
        }
        std::array<std::uint8_t,56> info{};unsigned n=0;
        switch(e){
            case 4:n=40;put(info,32,node.directory?0x10:0x1,8);break;
            case 6:n=8;put(info,0,index_of(file.path),8);break;
            case 14:n=8;put(info,0,file.position,8);break;
            case 17:n=4;break; // byte alignment
            case 19:case 20:n=8;put(info,0,node.bytes.size(),8);break;
            case 34:n=56;put(info,32,node.bytes.size(),8);put(info,40,node.bytes.size(),8);put(info,48,node.directory?0x10:0x1);break;
            default:return done(s,invalid_class);
        }
        if(d<n)return done(s,length_mismatch);
        if(!writable(memory_,c,n)||overlap(b,b?8:0,c,n))return ImportCallResult::fault;
        return memory.write(c,std::span(info).first(n))&&iosb(memory_,b,0,n)?done(s,0):ImportCallResult::fault;
    }
    if(o==0xe4){
        if(b||c||d)return ImportCallResult::unsupported;
        if(!node.directory)return done(s,not_directory);
        auto buffer=arg(s,5),length=arg(s,6),pattern_ptr=arg(s,7),restart=arg(s,8);
        if(length<72)return done(s,length_mismatch);
        if(length>max_io)return ImportCallResult::unsupported;
        if(e&&!writable(memory_,e,8))return ImportCallResult::fault;
        std::string pattern;if(!ascii(memory_,pattern_ptr,pattern))return ImportCallResult::fault;
        if(pattern.find_first_of("/\\:")!=std::string::npos)return done(s,invalid_name);
        if(pattern.empty()||pattern=="*.*")pattern="*";
        const bool first=!file.started||restart;
        if(first){
            file.scan.clear();file.cursor=0;file.started=true;
            for(const auto& [key,entry]:nodes_)
                if(parent(key)==file.path&&match(pattern,entry.display))file.scan.push_back(key);
        }
        if(file.cursor>=file.scan.size()){
            auto status=first?no_such_file:no_more_files;
            return iosb(memory_,e,status,0)?done(s,status):ImportCallResult::fault;
        }
        const auto& child=nodes_.at(file.scan[file.cursor]);
        auto n=static_cast<unsigned>(64+child.display.size());
        if(n>length)return iosb(memory_,e,buffer_overflow,0)?done(s,buffer_overflow):ImportCallResult::fault;
        if(!writable(memory_,buffer,n)||overlap(buffer,n,e,e?8:0))return ImportCallResult::fault;
        std::vector<std::uint8_t> info(n);
        put(info,4,file.cursor);put(info,40,child.bytes.size(),8);put(info,48,child.bytes.size(),8);
        put(info,56,child.directory?0x10:0x1);put(info,60,child.display.size());
        std::copy(child.display.begin(),child.display.end(),info.begin()+64);
        if(!memory.write(buffer,info)||!iosb(memory_,e,0,n))return ImportCallResult::fault;
        ++file.cursor;return done(s,0);
    }
    return ImportCallResult::unsupported;
}
}
