#pragma once
#include "model.hpp"
#include <filesystem>
#include <fstream>
namespace zs {
class Snapshot {
 std::ifstream stream;std::vector<std::uint8_t> data;std::string digest;
public:Snapshot(const std::filesystem::path&,std::uint64_t limit);Bytes bytes()const{return data;}void recheck();
};
void write_new(const std::string&,const std::filesystem::path&);
}
