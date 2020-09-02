#ifndef BACKTRACE_ELF_H
#define BACKTRACE_ELF_H

#ifdef __cplusplus
#include <link.h>
#include <sys/mman.h>

#include <map>
#include <vector>
namespace backtrace {
struct Function final {
  std::string name;
  const void* begin;
  size_t size;
  const void* end() const { return (uint8_t*)begin + size; }
};
class Elf final {
 public:
  Elf(const Elf&) = delete;
  Elf(Elf&&) = delete;
  Elf& operator=(const Elf&) = delete;
  Elf& operator=(Elf&&) = delete;

  Function* Locate(const void* pc);

  static Elf& Instance();

 private:
  Elf();
  ~Elf();

  void Parse();
  void ParseSelf();
  void ParseDl();
  bool OpenSelf();
  void ParseSectionHeader();
  void ParseSymtab(size_t index);
  const char* SectionName(size_t offset);
  const char* SymbolName(size_t offset);

  void AddFunc(ElfW(Sym) * sym, const char* strtab = nullptr,
               ElfW(Addr) offset = 0);

  static uint32_t ParseGnuHash(ElfW(Addr) addr);

  void* memory_ = MAP_FAILED;
  size_t length_ = 0;
  ElfW(Ehdr) * ehdr_ = nullptr;
  std::vector<ElfW(Shdr)*> shdrs_;
  ElfW(Shdr*) shstrtab_ = nullptr;
  ElfW(Shdr*) strtab_ = nullptr;
  std::map<const void*, Function> funcs_;
};
}  // namespace backtrace
#endif

#endif  // BACKTRACE_ELF_H
