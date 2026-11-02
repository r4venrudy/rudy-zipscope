#include "zipscope/model.hpp"
#include <iostream>
#include <cstdlib>
static int checks=0;
static void check(bool ok,const char* what){++checks;if(!ok){std::cerr<<what<<'\n';std::exit(1);}}
int main(){check(zs::version()=="0.1.0-preview","version");std::cout<<"ZipScope core checks passed: "<<checks<<'\n';}
