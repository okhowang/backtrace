#include "backtrace.h"

#include <asm/ptrace.h>  //for struct pt_regs
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#if !defined(__MIPSEB__) && !defined(__MIPSEL__)
#include <unwind.h>
#endif

static void unwind_print(const void *pc, const char *name, size_t offset,
                         void *userdata) {
  printf("\t=>%s()+0x%zu\n", name, offset);
}

#if defined(__MIPSEB__) || defined(__MIPSEL__)
struct mips_frame_info {
  void *func;
  unsigned long *ra;
  unsigned long func_size;
  int frame_size;
  int pc_offset;
};

static inline int is_jal_jalr_jr_ins(union mips_instruction *ip)
{
	if (ip->j_format.opcode == jal_op)
		return 1;
	if (ip->r_format.opcode != spec_op)
		return 0;
	return ip->r_format.func == jalr_op || ip->r_format.func == jr_op;
}

static inline int is_sp_move_ins(union mips_instruction *ip)
{
	/* addiu/daddiu sp,sp,-imm */
	if (ip->i_format.rs != 29 || ip->i_format.rt != 29)
		return 0;
	if (ip->i_format.opcode == addiu_op || ip->i_format.opcode == daddiu_op)
		return 1;
	return 0;
}

static inline int is_ra_save_ins(union mips_instruction *ip) {
  /* sw / sd $ra, offset($sp) */
  return (ip->i_format.opcode == sw_op || ip->i_format.opcode == sd_op) &&
         ip->i_format.rs == 29 && ip->i_format.rt == 31;
}

struct dwarf_eh_bases {
  void *tbase;
  void *dbase;
  void *func;
};
/* The first few fields of an FDE.  */
struct dwarf_fde {
  uint32_t length;
  int32_t CIE_delta;
  unsigned char pc_begin[];
} __attribute__((packed, aligned(__alignof__(void *))));
extern const struct dwarf_fde *_Unwind_Find_FDE(void *,
                                                struct dwarf_eh_bases *);

static pid_t hold_ra() {
  /* do nothing. */
  return getpid();
}

/* get general registers value.*/
static __always_inline void prepare_frametrace(struct pt_regs *regs) {
  pid_t _i = 0;
	_i = hold_ra(); //ensure ra is pointed to the function itself.
	printf("%d\n", _i);

        __asm__ __volatile__(
		".set noreorder\n\t"
		".set push\n\t"
		".set noat\n\t"

		"1: la $1, 1b\n\t"
		"sw $1, %0\n\t"
		"sw $29, %1\n\t"
		"sw $31, %2\n\t"

		".set pop\n\t"
		".set reorder\n\t"
		: "=m" (regs->cp0_epc),
		"=m" (regs->regs[29]), "=m" (regs->regs[31])
		: : "memory");
}

/* search for the position of target in ascending order base[].
return index in base[] if found target;
return the index that 'target' should be inserted into base[] if not found target, if target should be inserted at the front, return -1. */
static int bsearch_index(const unsigned long base[], int len, unsigned long target)
{
	int start = 0, end = len - 1;
	int middle;

        if (!base || base[0] > target)
	{
		return -1;
	}
	if (base[len - 1] < target)
	{
		return (len - 1);
	}

	/* binary search */
	while (start <= end)
	{
		middle = (start + end) / 2;
		if (base[middle] == target)
		{
			return middle;
		}
		if (base[end] == target)
		{
			return end;
		}
		if ((start + 1 == end) || (start == end))
		{
			return start;
		}

                /* always ensure start < target, and end > end */
		if (base[middle] > target)
		{
                  end = middle;
                }
                if (base[middle] < target) {
                  start = middle;
                }
        }

        return -1;
}
#endif

#if defined(__MIPSEB__) || defined(__MIPSEL__)
/* recursively look for sp and ra. sp for stack address space, ra for text
 * section. */
static void do_backtrace(unsigned long sp, unsigned long ra,
                         void (*callback)(const void *pc, const char *name,
                                          size_t offset, void *userdata),
                         void *userdata) {
  int index = 0;
  union mips_instruction *ip;
  unsigned int max_insns;
  unsigned int i;
  struct mips_frame_info info;
  const char *caller_name = NULL;
  size_t offset;

  memset(&info, 0, sizeof(info));

  caller_name = addr_to_name((const void *)ra);
  if (caller_name == NULL) return;
  offset = addr_to_offset((const void *)ra);

  ip = (union mips_instruction *)(ra - offset);
  if (!ip) {
    return;
  }

  if (callback)
    callback((const void *)ra, caller_name, ra - (unsigned long)ip, userdata);

  /* only search in instructions already executed. */
  max_insns = (ra - (unsigned long)ip) / sizeof(union mips_instruction);
  if (max_insns == 0) {
    max_insns = 128U; /* unknown function size */
  }
  max_insns = max_insns < 128U ? max_insns : 128U;

  info.func = ip;
  info.frame_size = 0;
  info.func_size = 0; //not used
	info.pc_offset = -1; //not used
	info.ra = NULL;

	/* find sp and ra (userspace functions use fp, so sp is not changed) */
	for (i = 0; i < max_insns; i++, ip++)
	{
		if (is_jal_jalr_jr_ins(ip))
			break;
		if (!info.frame_size) {
			if (is_sp_move_ins(ip))
			{
				info.frame_size = - ip->i_format.simmediate; //size of function stack
			}
			continue;
		}
		if (info.pc_offset == -1 && is_ra_save_ins(ip)) { //find ra
			info.ra = (unsigned long *)(sp + ip->i_format.simmediate);
			break;
		}
	}

        /* jump to caller's stack. */
        sp = sp + info.frame_size;

        if (info.ra) {
          do_backtrace(sp, *(info.ra), callback, userdata);
        }
}

void backtrace_run(const ucontext_t *ucontext,
                   void (*callback)(const void *pc, const char *name,
                                    size_t offset, void *userdata),
                   void *userdata) {
  unsigned long sp, ra;
  if (ucontext) {
    sp = ucontext->uc_mcontext.gregs[29];
    ra = ucontext->uc_mcontext.gregs[31];
  } else {
    struct pt_regs regs;
    prepare_frametrace(&regs);
    sp = regs.regs[29];
    ra = regs.regs[31];
  }
  do_backtrace(sp, ra, callback, userdata);
}

/* print back trace functions */
void show_backtrace() {
  printf("Call trace:\n");
  backtrace_run(NULL, unwind_print, NULL);
  printf("\n");
}

void show_backtrace_ucontext(const ucontext_t *ucontext) {
  printf("Call trace:\n");
  backtrace_run(ucontext, unwind_print, NULL);
  printf("\n");
}

#else

struct BacktraceData {
  void (*callback)(const void *pc, const char *name, size_t offset,
                   void *userdata);
  void *userdata;
};

static _Unwind_Reason_Code unwind_wrapper(struct _Unwind_Context *context,
                                          void *data) {
  struct BacktraceData *userdata = data;
  const void *ip = (const void *)_Unwind_GetIP(context);
  if (!ip) return _URC_END_OF_STACK;
  if (userdata->callback)
    userdata->callback(ip, addr_to_name(ip), addr_to_offset(ip),
                       userdata->userdata);
  return _URC_NO_REASON;
}

void show_backtrace() {
  printf("Call trace:\n");
  backtrace_run(NULL, unwind_print, NULL);
  printf("\n");
}

void show_backtrace_ucontext(const struct ucontext *ucontext) {
  show_backtrace();
}

void backtrace_run(const ucontext_t *ucontext,
                   void (*callback)(const void *pc, const char *name,
                                    size_t offset, void *userdata),
                   void *userdata) {
  struct BacktraceData data = {callback, userdata};
  _Unwind_Backtrace(unwind_wrapper, &data);
}

#endif
