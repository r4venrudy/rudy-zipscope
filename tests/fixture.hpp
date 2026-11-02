#pragma once
#include "zipscope/bytes.hpp"
using V = std::vector<std::uint8_t>;
inline void p16(V &b, std::uint16_t v) {
    b.push_back(static_cast<std::uint8_t>(v));
    b.push_back(static_cast<std::uint8_t>(v >> 8));
}
inline void p32(V &b, std::uint32_t v) {
    p16(b, static_cast<std::uint16_t>(v));
    p16(b, static_cast<std::uint16_t>(v >> 16));
}
inline void set16(V &b, std::size_t p, std::uint16_t v) {
    b.at(p) = static_cast<std::uint8_t>(v);
    b.at(p + 1) = static_cast<std::uint8_t>(v >> 8);
}
inline void set32(V &b, std::size_t p, std::uint32_t v) {
    set16(b, p, static_cast<std::uint16_t>(v));
    set16(b, p + 2, static_cast<std::uint16_t>(v >> 16));
}
inline V zip(std::string name = "safe.txt") {
    V b;
    p32(b, 0x04034b50);
    p16(b, 20);
    p16(b, 0x800);
    p16(b, 0);
    p32(b, 0);
    p32(b, 0x352441c2);
    p32(b, 3);
    p32(b, 3);
    p16(b, static_cast<std::uint16_t>(name.size()));
    p16(b, 0);
    b.insert(b.end(), name.begin(), name.end());
    b.insert(b.end(), {'a', 'b', 'c'});
    auto c = b.size();
    p32(b, 0x02014b50);
    p16(b, 0x314);
    p16(b, 20);
    p16(b, 0x800);
    p16(b, 0);
    p32(b, 0);
    p32(b, 0x352441c2);
    p32(b, 3);
    p32(b, 3);
    p16(b, static_cast<std::uint16_t>(name.size()));
    p16(b, 0);
    p16(b, 0);
    p16(b, 0);
    p16(b, 0);
    p32(b, 0x81a40000);
    p32(b, 0);
    b.insert(b.end(), name.begin(), name.end());
    auto size = b.size() - c;
    p32(b, 0x06054b50);
    p16(b, 0);
    p16(b, 0);
    p16(b, 1);
    p16(b, 1);
    p32(b, static_cast<std::uint32_t>(size));
    p32(b, static_cast<std::uint32_t>(c));
    p16(b, 0);
    return b;
}
template <class F> inline bool rejects(F f, const std::string &code = "") {
    try {
        f();
    } catch (const zs::Error &e) {
        return code.empty() || e.code == code;
    }
    return false;
}
