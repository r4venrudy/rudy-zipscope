#include "zipscope/io.hpp"
#include "zipscope/hash.hpp"
#include <array>
#ifdef _WIN32
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <cerrno>
#include <fcntl.h>
#include <unistd.h>
#endif
namespace zs {
Snapshot::Snapshot(const std::filesystem::path &path, std::uint64_t limit)
    : stream(path, std::ios::binary) {
    if (!stream || !std::filesystem::is_regular_file(path))
        throw Error("INPUT_IO", 0);
    stream.seekg(0, std::ios::end);
    auto size = stream.tellg();
    if (size < 0 || static_cast<std::uint64_t>(size) > limit)
        throw Error("INPUT_LIMIT", 0);
    data.resize(static_cast<std::size_t>(size));
    stream.seekg(0);
    if (!data.empty())
        stream.read(reinterpret_cast<char *>(data.data()),
                    static_cast<std::streamsize>(data.size()));
    if (!stream)
        throw Error("INPUT_CHANGED", 0);
    digest = sha256(data);
}
void Snapshot::recheck() {
    stream.clear();
    stream.seekg(0);
    std::array<std::uint8_t, 65536> block{};
    Sha256 hash;
    std::uint64_t count = 0;
    while (stream) {
        stream.read(reinterpret_cast<char *>(block.data()),
                    static_cast<std::streamsize>(block.size()));
        auto n = stream.gcount();
        if (n < 0 || static_cast<std::uint64_t>(n) >
                         data.size() - std::min<std::uint64_t>(count, data.size()))
            throw Error("INPUT_CHANGED", count);
        count += static_cast<std::uint64_t>(n);
        hash.update(Bytes(block.data(), static_cast<std::size_t>(n)));
    }
    if (!stream.eof() || count != data.size() || hash.finish() != digest)
        throw Error("INPUT_CHANGED", count);
}
void write_new(const std::string &content, const std::filesystem::path &path) {
    if (content.size() > 16 * 1024 * 1024)
        throw Error("REPORT_LIMIT", 0);
#ifdef _WIN32
    auto file = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
                            FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE)
        throw Error("OUTPUT_CREATE", 0);
    struct Close {
        HANDLE f;
        ~Close() {
            CloseHandle(f);
        }
    } close{file};
    std::size_t offset = 0;
    while (offset < content.size()) {
        DWORD written = 0;
        auto n = static_cast<DWORD>(std::min<std::size_t>(content.size() - offset, 1024 * 1024));
        if (!WriteFile(file, content.data() + offset, n, &written, nullptr) || written == 0)
            throw Error("OUTPUT_IO", offset);
        offset += written;
    }
#else
    int file = open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (file < 0)
        throw Error("OUTPUT_CREATE", 0);
    struct Close {
        int f;
        ~Close() {
            ::close(f);
        }
    } close{file};
    std::size_t offset = 0;
    while (offset < content.size()) {
        auto n = ::write(file, content.data() + offset, content.size() - offset);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            throw Error("OUTPUT_IO", offset);
        offset += static_cast<std::size_t>(n);
    }
#endif
}
} // namespace zs
