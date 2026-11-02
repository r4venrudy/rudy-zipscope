#include "zipscope/model.hpp"
#include "zipscope/bytes.hpp"
#include "zipscope/hash.hpp"
#include <iostream>
#include <cstdlib>
static int checks=0;
static void check(bool ok,const char* what){++checks;if(!ok){std::cerr<<what<<'\n';std::exit(1);}}
int main(){check(zs::version()=="0.1.0-preview","version");std::vector<std::uint8_t> b{0x12,0x34,0x56,0x78};check(zs::u32(b,0)==0x78563412,"little endian");bool rejected=false;try{zs::slice(b,UINT64_MAX,2);}catch(const zs::Error&){rejected=true;}check(rejected,"overflow-safe bounds");check(zs::sha256({})=="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","SHA empty");std::vector<std::uint8_t> abc{'a','b','c'};check(zs::sha256(abc)=="ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad","SHA abc");std::cout<<"ZipScope core checks passed: "<<checks<<'\n';}
