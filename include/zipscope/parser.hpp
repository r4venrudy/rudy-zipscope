#pragma once
#include "model.hpp"
namespace zs {
Directory directory(Bytes);
std::vector<Entry> central(Bytes, const Directory &, const Limits &);
void local(Bytes, Entry &);
void descriptor(Bytes, Entry &);
Report analyze(Bytes, const Limits & = {});
} // namespace zs
