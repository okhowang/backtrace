#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

#include <exception>

#include "backtrace.h"

int func2(int a, int b);
int func1(int a, int b);
int func0(int a, int b);

int func2(int a, int b) {
  int c = a * b;
  printf("%s: c = %d\n", __FUNCTION__, c);
  show_backtrace();
  return c;
}

int func1(int a, int b) {
  int c = func2(a, b);
  printf("%s: c = %d\n", __FUNCTION__, c);
  return c;
}

void handler(int no, siginfo_t *info, void *ctx) {
  ucontext_t *context = static_cast<ucontext_t *>(ctx);
  show_backtrace_ucontext(context);
  exit(0);
}

int func0(int a, int b) {
  int c = func1(a, b);
  printf("%s: c = %d\n", __FUNCTION__, c);
  return c;
}

void abortFunction() { abort(); }

void abortFunction1() { abortFunction(); }

void exceptionFunction() { throw std::exception(); }

void exceptionFunction1() { exceptionFunction(); }

int main() noexcept {
  struct sigaction sega;
  sega.sa_sigaction = handler;
  sega.sa_flags = SA_SIGINFO;
  sigemptyset(&sega.sa_mask);
  sigaction(SIGABRT, &sega, NULL);
  int a = 4, b = 5;
  int (*funcptr)(int, int) = func0;

  int c = func0(a, b);
  printf("%s: c = %d\n", __FUNCTION__, c);

  printf("funcptr's name = %s\n",
         addr_to_name(reinterpret_cast<const void *>(funcptr)));
  if (0)
    abortFunction1();
  else
    exceptionFunction1();
  return 0;
}
