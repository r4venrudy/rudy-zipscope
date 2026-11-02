#pragma once
#include <cstdint>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>
namespace zs {
using Bytes=std::span<const std::uint8_t>;
struct Error:std::runtime_error { std::string code;std::uint64_t offset;Error(std::string c,std::uint64_t o):std::runtime_error(c),code(std::move(c)),offset(o){} };
struct Finding {std::string code;std::size_t entry;std::string severity;};
struct Limits {std::uint64_t input=256*1024*1024,total=512*1024*1024,entry=64*1024*1024;std::size_t entries=10000;};
struct Entry {
 std::string name,local_name,sha256,prefix;std::uint16_t method=0,flags=0,made_by=0,needed=0;std::uint32_t crc=0,attrs=0;
 std::uint64_t compressed=0,size=0,local=0,data=0,end=0;bool verified=false,directory=false,symlink=false;
 std::vector<std::uint8_t> extra,local_extra;
};
struct Directory {std::uint64_t start=0,size=0,count=0,end=0,eocd=0;bool zip64=false;};
struct Gap {std::uint64_t begin,end;std::string sha256;};
struct Report {bool complete=false;std::string sha256,stop_code;std::uint64_t stop_offset=0;Directory directory;std::vector<Entry> entries;std::vector<Finding> findings;std::vector<Gap> gaps;};
std::string version();
}
