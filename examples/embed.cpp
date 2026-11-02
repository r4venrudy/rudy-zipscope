#include "zipscope/output.hpp"
#include "zipscope/parser.hpp"
#include <iostream>
int main() {
    // An invented empty single-disk ZIP: one 22-byte EOCD record.
    std::vector<std::uint8_t> archive(22, 0);
    archive[0] = 0x50;
    archive[1] = 0x4b;
    archive[2] = 0x05;
    archive[3] = 0x06;
    const auto report = zs::analyze(archive);
    std::cout << zs::json(report);
    return report.complete && report.entries.empty() ? 0 : 2;
}
