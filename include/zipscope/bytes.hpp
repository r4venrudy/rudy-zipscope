#pragma once
#include "model.hpp"
namespace zs {
inline Bytes slice(Bytes b,std::uint64_t p,std::uint64_t n){if(p>b.size()||n>b.size()-p)throw Error("TRUNCATED",p);return b.subspan(static_cast<std::size_t>(p),static_cast<std::size_t>(n));}
inline std::uint16_t u16(Bytes b,std::uint64_t p){auto s=slice(b,p,2);return static_cast<std::uint16_t>(s[0]|(static_cast<std::uint16_t>(s[1])<<8));}
inline std::uint32_t u32(Bytes b,std::uint64_t p){auto s=slice(b,p,4);return static_cast<std::uint32_t>(s[0])|(static_cast<std::uint32_t>(s[1])<<8)|(static_cast<std::uint32_t>(s[2])<<16)|(static_cast<std::uint32_t>(s[3])<<24);}
inline std::uint64_t u64(Bytes b,std::uint64_t p){return u32(b,p)|(static_cast<std::uint64_t>(u32(b,p+4))<<32);}
inline std::string raw(Bytes b){return {reinterpret_cast<const char*>(b.data()),b.size()};}
}
