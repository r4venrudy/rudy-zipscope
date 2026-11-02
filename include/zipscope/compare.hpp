#pragma once
#include "model.hpp"
namespace zs {
struct Difference {
    std::string name, change, before, after;
};
struct Comparison {
    bool comparable = false, equal = false;
    std::string before, after;
    std::vector<Difference> differences;
};
Comparison compare(const Report &, const Report &);
std::string json(const Comparison &, bool names = false);
} // namespace zs
