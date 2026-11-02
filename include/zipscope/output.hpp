#pragma once
#include "model.hpp"
namespace zs {
std::string json(const Report &, bool names = false);
std::string text(const Report &, bool names = false);
std::string html(const Report &, bool names = false);
std::string sarif(const Report &, bool names = false);
} // namespace zs
