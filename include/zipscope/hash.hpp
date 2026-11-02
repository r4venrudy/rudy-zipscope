#pragma once
#include "model.hpp"
#include <array>
namespace zs {
class Sha256 {
 std::array<std::uint32_t,8> state{0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
 std::array<std::uint8_t,64> buffer{};std::size_t used=0;std::uint64_t length=0;
 void block(const std::uint8_t*);
public:void update(Bytes);std::string finish() const;
};
inline std::string sha256(Bytes b){Sha256 s;s.update(b);return s.finish();}
}
