//CONFIG.h
#define __STDLIB__ 1
#define __SYSTYPES__ 1
#define __STRING__ 1
#define __FCNTL__ 1
#define __SGTTY__ 1
#define __PWD__ 1
#define __TIME__ 1
#define __SYSRESOURCE__ 1
#define __ERRNO__ 1
#define __SYSTIME__ 1
#define __SYSTIMEB__ 1
#define __QUOTA__ 1
#define __SYSPARAM__ 1
#undef __SHADOW__
#undef __SYSINFO__
#define __UNISTD__ 1
//DEBUG START
#define _d_enter_func(file, count, func, ...)\
  if(dLevel > 0) debug_1_enter(file, func);\
  if(dLevel > 2) debug_3_enter(file, count, func, __VA_ARGS__);
#define _d_exit_func(file, func, val)\
  if(dLevel > 0) debug_1_exit(file, func);\
  if(dLevel > 1) debug_2_exit(file, val);
#define logfile (logging == 1) ? logFile : NULL
