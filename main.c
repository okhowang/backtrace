#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

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
  ucontext_t *context = ctx;
  show_backtrace_ucontext(context);
  exit(0);
}

int func0(int a, int b) {
  int c = func1(a, b);
  printf("%s: c = %d\n", __FUNCTION__, c);
  return c;
}

int abortFunction() { abort(); }

int abortFunction1() { abortFunction(); }

int main() {
  struct sigaction sega;
  sega.sa_sigaction = handler;
  sega.sa_flags = SA_SIGINFO;
  sigemptyset(&sega.sa_mask);
  sigaction(SIGABRT, &sega, NULL);
  int a = 4, b = 5;
  int (*funcptr)(int, int) = func0;

  int c = func0(a, b);
  printf("%s: c = %d\n", __FUNCTION__, c);

  printf("funcptr's name = %s\n", addr_to_name(funcptr));
  abortFunction1();
  return 0;
}
