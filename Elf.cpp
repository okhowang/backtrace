#include "Elf.h"

#include <cxxabi.h>
#include <fcntl.h>
#include <link.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstdlib>
#include <cstring>

#include "backtrace.h"

#if UINTPTR_MAX > 0xffffffff
#define ElfM(type) ELF64_##type
#else
#define ElfM(type) ELF32_##type
#endif

namespace backtrace {

class unique_fd {
 public:
  explicit unique_fd(int fd = -1) : fd_(fd){};
  ~unique_fd() {
    if (fd_ != -1) close(fd_);
  }

  unique_fd(const unique_fd&) = delete;
  unique_fd(unique_fd&& other) noexcept : fd_(other.fd_) { other.fd_ = -1; }
  unique_fd& operator=(const unique_fd&) = delete;
  unique_fd& operator=(unique_fd&& other) noexcept {
    fd_ = other.fd_;
    other.fd_ = -1;
    return *this;
  }

  operator int() const { return fd_; }
  bool operator==(int fd) const { return fd == fd_; }

 private:
  int fd_;
};

Elf& backtrace::Elf::Instance() {
  static Elf elf;
  return elf;
}

Elf::Elf() { Parse(); }

Elf::~Elf() {
  if (memory_ != MAP_FAILED) munmap(memory_, length_);
}

void Elf::Parse() {
  ParseSelf();
  ParseDl();
}

uint32_t Elf::ParseGnuHash(ElfW(Addr) addr) {
  // See https://flapenguin.me/2017/05/10/elf-lookup-dt-gnu-hash/ and
  // https://sourceware.org/ml/binutils/2006-10/msg00377.html
  typedef struct {
    uint32_t nbuckets;
    uint32_t symoffset;
    uint32_t bloom_size;
    uint32_t bloom_shift;
  } Header;

  Header* header = (Header*)addr;
  uint8_t* bucketsAddress =
      (uint8_t*)addr + sizeof(Header) + (sizeof(uint64_t) * header->bloom_size);

  // Locate the chain that handles the largest index bucket.
  uint32_t lastSymbol = 0;
  uint32_t* bucketAddress = (uint32_t*)bucketsAddress;
  for (uint32_t i = 0; i < header->nbuckets; ++i) {
    uint32_t bucket = *bucketAddress;
    if (lastSymbol < bucket) {
      lastSymbol = bucket;
    }
    bucketAddress++;
  }

  if (lastSymbol < header->symoffset) {
    return header->symoffset;
  }

  // Walk the bucket's chain to add the chain length to the total.
  const uint8_t* chainBaseAddress =
      bucketsAddress + (sizeof(uint32_t) * header->nbuckets);
  for (;;) {
    uint32_t* chainEntry =
        (uint32_t*)(chainBaseAddress +
                    (lastSymbol - header->symoffset) * sizeof(uint32_t));
    lastSymbol++;

    // If the low bit is set, this entry is the end of the chain.
    if (*chainEntry & 1) {
      break;
    }
  }

  return lastSymbol;
}

void Elf::ParseDl() {
  dl_iterate_phdr(
      [](struct dl_phdr_info* info, size_t size, void* that) -> int {
        auto self = static_cast<Elf*>(that);
        for (int i = 0; i < info->dlpi_phnum; i++) {
          if (info->dlpi_phdr[i].p_type != PT_DYNAMIC) continue;
          ElfW(Word) symCnt = 0;
          ElfW(Word) gnuSymCnt = 0;
          ElfW(Sym)* symtab = nullptr;
          const char* strtab = nullptr;
          for (auto dyn = reinterpret_cast<ElfW(Dyn)*>(
                   info->dlpi_addr + info->dlpi_phdr[i].p_vaddr);
               dyn->d_tag != DT_NULL; dyn++)
            switch (dyn->d_tag) {
              case DT_HASH: {
                if (dyn->d_un.d_ptr >= info->dlpi_addr) {
                  auto hash = (ElfW(Word*))dyn->d_un.d_ptr;
                  symCnt = hash[1];
                } else {
                  // TODO vdso printf("bad address\n");
                }
              } break;
              case DT_GNU_HASH:
                if (dyn->d_un.d_ptr >= info->dlpi_addr) {
                  gnuSymCnt = ParseGnuHash(dyn->d_un.d_ptr);
                } else {
                  // TODO vdso printf("bad address\n");
                }
                break;
              case DT_STRTAB:
                strtab = reinterpret_cast<const char*>(dyn->d_un.d_ptr);
                break;
              case DT_SYMTAB:
                symtab = reinterpret_cast<ElfW(Sym)*>(dyn->d_un.d_ptr);
            }
          if (gnuSymCnt == 0) gnuSymCnt = symCnt;
          for (ElfW(Word) symIndex = 0; symIndex < gnuSymCnt; symIndex++) {
            self->AddFunc(&symtab[symIndex], strtab, info->dlpi_addr);
          }
        }
        return 0;
      },
      this);
}

void Elf::ParseSelf() {
  if (!OpenSelf()) return;
  ehdr_ = static_cast<ElfW(Ehdr)*>(memory_);
  ParseSectionHeader();
}

void Elf::ParseSectionHeader() {
  // parse .shstrtab firstly
  shstrtab_ =
      reinterpret_cast<ElfW(Shdr)*>((uint8_t*)memory_ + ehdr_->e_shoff +
                                    ehdr_->e_shstrndx * (ehdr_->e_shentsize));
  for (int i = 0; i < ehdr_->e_shnum; i++) {
    ElfW(Shdr)* shdr = reinterpret_cast<ElfW(Shdr)*>(
        (uint8_t*)memory_ + ehdr_->e_shoff + i * (ehdr_->e_shentsize));
    shdrs_.emplace_back(shdr);
  }
  // parse .strtab secondly
  for (int i = 0; i < ehdr_->e_shnum; i++) {
    if (shdrs_[i]->sh_type == SHT_STRTAB &&
        strcmp(SectionName(shdrs_[i]->sh_name), ".strtab") == 0) {
      strtab_ = shdrs_[i];
      break;
    }
  }
  for (int i = 0; i < ehdr_->e_shnum; i++) {
    if (shdrs_[i]->sh_type == SHT_SYMTAB &&
        strcmp(SectionName(shdrs_[i]->sh_name), ".symtab") == 0) {
      ParseSymtab(i);
    }
  }
}

void Elf::ParseSymtab(size_t index) {
  ElfW(Shdr)* shdr = shdrs_[index];
  auto* sym = reinterpret_cast<ElfW(Sym)*>((uint8_t*)memory_ + shdr->sh_offset);
  auto* end = reinterpret_cast<ElfW(Sym)*>((uint8_t*)memory_ + shdr->sh_offset +
                                           shdr->sh_size);
  for (; sym < end; sym++) {
    AddFunc(sym);
  }
}

bool Elf::OpenSelf() {
  std::string path("/proc/self/exe");
  struct stat sb;
  do {
    if (lstat(path.c_str(), &sb) == -1) {
      return false;
    }
    if (!S_ISLNK(sb.st_mode)) {
      break;
    }
    std::string buffer;
    buffer.resize(sb.st_size == 0 ? 1024 : sb.st_size);
    int ret =
        readlink(path.c_str(), const_cast<char*>(buffer.data()), buffer.size());
    if (ret == -1) return false;
    path = buffer.substr(0, ret);
  } while (true);
  auto fd = unique_fd(open(path.c_str(), O_RDONLY));
  if (fd == -1) return false;
  if (fstat(fd, &sb) == -1) return false;
  length_ = sb.st_size;
  memory_ = mmap(nullptr, length_, PROT_READ, MAP_PRIVATE, fd, 0);
  if (memory_ == MAP_FAILED) {
    return false;
  }
  return true;
}
const char* Elf::SectionName(size_t offset) {
  return (const char*)memory_ + shstrtab_->sh_offset + offset;
}
const char* Elf::SymbolName(size_t offset) {
  return (const char*)memory_ + strtab_->sh_offset + offset;
}
Function* Elf::Locate(const void* pc) {
  auto func = funcs_.lower_bound(pc);
  if (func == funcs_.end()) {
    if (funcs_.rbegin()->second.end() >= pc) return &funcs_.rbegin()->second;
    return nullptr;
  } else if (func->second.begin > pc) {
    if (func == funcs_.begin()) return nullptr;
    func--;
  }
  if (func->second.end() >= pc) return &func->second;
  return nullptr;
}
void Elf::AddFunc(ElfW(Sym) * sym, const char* strtab, ElfW(Addr) offset) {
  if (ElfM(ST_TYPE)(sym->st_info) != STT_FUNC) return;
  const char* name = strtab ? strtab + sym->st_name : SymbolName(sym->st_name);
  char* demangled = abi::__cxa_demangle(name, nullptr, nullptr, nullptr);
  if (demangled != nullptr) {
    name = demangled;
  }
  auto result = funcs_.emplace(
      reinterpret_cast<const void*>(sym->st_value + offset),
      Function{.name = name,
               .begin = reinterpret_cast<const void*>(sym->st_value + offset),
               .size = sym->st_size});
  if (demangled != nullptr) free(demangled);
}
}  // namespace backtrace

const char* addr_to_name(const void* p) {
  auto func = backtrace::Elf::Instance().Locate(p);
  return func ? func->name.c_str() : nullptr;
}

size_t addr_to_offset(const void* p) {
  auto func = backtrace::Elf::Instance().Locate(p);
  return func ? (uint8_t*)p - (uint8_t*)func->begin : 0;
}