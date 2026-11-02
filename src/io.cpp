#include "zipscope/io.hpp"
#include "zipscope/hash.hpp"
#include <array>
namespace zs {
Snapshot::Snapshot(const std::filesystem::path&path,std::uint64_t limit):stream(path,std::ios::binary){
 if(!stream||!std::filesystem::is_regular_file(path))throw Error("INPUT_IO",0);stream.seekg(0,std::ios::end);auto size=stream.tellg();if(size<0||static_cast<std::uint64_t>(size)>limit)throw Error("INPUT_LIMIT",0);
 data.resize(static_cast<std::size_t>(size));stream.seekg(0);if(!data.empty())stream.read(reinterpret_cast<char*>(data.data()),static_cast<std::streamsize>(data.size()));if(!stream)throw Error("INPUT_CHANGED",0);digest=sha256(data);
}
void Snapshot::recheck(){stream.clear();stream.seekg(0);std::array<std::uint8_t,65536> block{};Sha256 hash;std::uint64_t count=0;while(stream){stream.read(reinterpret_cast<char*>(block.data()),static_cast<std::streamsize>(block.size()));auto n=stream.gcount();if(n<0||static_cast<std::uint64_t>(n)>data.size()-std::min<std::uint64_t>(count,data.size()))throw Error("INPUT_CHANGED",count);count+=static_cast<std::uint64_t>(n);hash.update(Bytes(block.data(),static_cast<std::size_t>(n)));}if(!stream.eof()||count!=data.size()||hash.finish()!=digest)throw Error("INPUT_CHANGED",count);}
}
