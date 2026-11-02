#pragma once
#include "model.hpp"
namespace zs {
Directory directory(Bytes);
std::vector<Entry> central(Bytes,const Directory&,const Limits&);
void local(Bytes,Entry&);
}
