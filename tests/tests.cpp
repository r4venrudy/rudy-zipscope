#include "zipscope/model.hpp"
#include "zipscope/bytes.hpp"
#include "zipscope/hash.hpp"
#include "zipscope/parser.hpp"
#include "fixture.hpp"
#include "zipscope/extra.hpp"
#include <iostream>
#include <cstdlib>
static int checks=0;
static void check(bool ok,const char* what){++checks;if(!ok){std::cerr<<what<<'\n';std::exit(1);}}
struct AutoTest{explicit AutoTest(void(*fn)()){fn();}};
#define TEST(name) static void name();static AutoTest run_##name(name);static void name()
TEST(footer){auto b=zip();auto d=zs::directory(b);check(d.count==1&&d.start==41&&d.size==54,"EOCD boundaries");b.push_back(0);check(rejects([&]{zs::directory(b);}),"reject trailing bytes");b=zip();set16(b,b.size()-18,1);check(rejects([&]{zs::directory(b);},"MULTI_DISK"),"single disk profile");}
TEST(zip64_footer){auto b=zip();auto old=V(b.end()-22,b.end());b.resize(b.size()-22);auto z=b.size();p32(b,0x06064b50);p32(b,44);p32(b,0);p16(b,45);p16(b,45);p32(b,0);p32(b,0);p32(b,1);p32(b,0);p32(b,1);p32(b,0);p32(b,54);p32(b,0);p32(b,41);p32(b,0);p32(b,0x07064b50);p32(b,0);p32(b,static_cast<std::uint32_t>(z));p32(b,0);p32(b,1);set16(old,8,0xffff);set16(old,10,0xffff);set32(old,12,0xffffffff);set32(old,16,0xffffffff);b.insert(b.end(),old.begin(),old.end());auto d=zs::directory(b);check(d.zip64&&d.count==1&&d.start==41,"ZIP64 end and locator");set32(b,z+48,42);check(rejects([&]{zs::directory(b);}),"ZIP64 directory cannot cross end records");}
TEST(central_records){auto b=zip();auto d=zs::directory(b);auto e=zs::central(b,d,{});check(e.size()==1&&e[0].name=="safe.txt"&&e[0].size==3&&e[0].crc==0x352441c2,"central exact record");zs::Limits l;l.entries=0;check(rejects([&]{zs::central(b,d,l);},"ENTRY_LIMIT"),"entry budget before allocation");d.size--;check(rejects([&]{zs::central(b,d,{});}),"central bounded lengths");}
TEST(extra_fields){zs::Entry e;e.size=0xffffffff;e.extra={1,0,8,0,3,0,0,0,0,0,0,0};zs::zip64_values(e);check(e.size==3,"ZIP64 sentinel expansion");check(rejects([]{zs::extras(V{1,0,8,0});}),"truncated extra");check(rejects([]{zs::extras(V{1,0,0,0,1,0,0,0});}),"duplicate extra ambiguity");}
TEST(local_records){auto b=zip();auto e=zs::central(b,zs::directory(b),{})[0];zs::local(b,e);check(e.data==38&&e.end==41&&e.local_name==e.name,"local record data interval");set16(b,8,8);check(rejects([&]{zs::local(b,e);},"HEADER_DISAGREEMENT"),"local method conflict");}
TEST(local_zip64){auto b=zip();auto e=zs::central(b,zs::directory(b),{})[0];set32(b,18,0xffffffff);set32(b,22,0xffffffff);set16(b,28,20);V x{1,0,16,0,3,0,0,0,0,0,0,0,3,0,0,0,0,0,0,0};b.insert(b.begin()+38,x.begin(),x.end());zs::local(b,e);check(e.data==58&&e.end==61,"local ZIP64 resolved");b[42]=4;check(rejects([&]{zs::local(b,e);}),"ZIP64 local size mismatch");}
TEST(data_descriptors){for(bool sign:{false,true})for(bool wide:{false,true}){auto b=zip();auto e=zs::central(b,zs::directory(b),{})[0];e.flags|=8;set16(b,6,e.flags);set32(b,14,0);set32(b,18,0);set32(b,22,0);b.resize(41);if(sign)p32(b,0x08074b50);p32(b,e.crc);p32(b,3);if(wide)p32(b,0);p32(b,3);if(wide)p32(b,0);zs::local(b,e);zs::descriptor(b,e);check(e.end==b.size(),"signed/unsigned narrow/wide descriptor");}}
int main(){check(zs::version()=="0.1.0-preview","version");std::vector<std::uint8_t> b{0x12,0x34,0x56,0x78};check(zs::u32(b,0)==0x78563412,"little endian");bool rejected=false;try{zs::slice(b,UINT64_MAX,2);}catch(const zs::Error&){rejected=true;}check(rejected,"overflow-safe bounds");check(zs::sha256({})=="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","SHA empty");std::vector<std::uint8_t> abc{'a','b','c'};check(zs::sha256(abc)=="ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad","SHA abc");std::cout<<"ZipScope core checks passed: "<<checks<<'\n';}
