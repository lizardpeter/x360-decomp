#pragma once
#include "formats/xui.hpp"
#include <map>
#include <string>
namespace x360::formats::xui {
struct ResourceDescriptor {std::string id;std::size_t offset,size;};
// Owns decoded bytes so borrowed archive and scene views stay valid. The
// original input identity is verified by the source audit/loader before intake.
class Catalog {
public:
    static Catalog open(std::vector<std::uint8_t> image,std::span<const ResourceDescriptor> resources);
    Catalog(const Catalog&)=delete;
    Catalog& operator=(const Catalog&)=delete;
    Catalog(Catalog&&)=default;
    Catalog& operator=(Catalog&&)=delete;
    std::size_t resource_count() const noexcept{return resources_.size();}
    std::size_t archive_count() const noexcept{return archives_.size();}
    std::optional<Bytes> resource(std::string_view id) const;
    const Archive* archive(std::string_view id) const;
    std::optional<Bytes> find(std::string_view archive_id,std::string_view member) const;
    std::optional<Scene> scene(std::string_view archive_id,std::string_view member) const;
    std::optional<StringTable> strings(std::string_view archive_id,std::string_view member) const;
private:
    Catalog()=default;
    std::vector<std::uint8_t> image_;
    std::map<std::string,Bytes,std::less<>> resources_;
    std::map<std::string,Archive,std::less<>> archives_;
};
}
