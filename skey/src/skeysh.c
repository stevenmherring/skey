/* S/KEY v1.1b (skeysh.c)
 *
 * Authors:
 *          Neil M. Haller <nmh@thumper.bellcore.com>
 *          Philip R. Karn <karn@chicago.qualcomm.com>
 *          John S. Walden <jsw@thumper.bellcore.com>
 *          Scott Chasin <chasin@crimelab.com>
 *
 * S/Key authentication shell
 */
#include "config.h"
#include "skey.h"

#ifdef __STDIO__
#include <stdio.h>
#endif

#ifdef __STRING__
#include <string.h>
#endif

#ifdef __UNISTD__
#include <unistd.h>
#endif

#ifdef __SYSTYPES__
#include <sys/types.h>
#endif

#ifdef __PWD__
#include <pwd.h>
#endif

#ifdef __GRP__
#include <grp.h>
#endif

#ifdef __SYSGRP__
#include <sys/grp.h>
#endif

#ifdef __STDLIB__
#include <stdlib.h>
#endif

char userbuf[16] = "USER=";
char homebuf[128] = "HOME=";
char shellbuf[128] = "SHELL=";
char pathbuf[128] = "PATH=:/usr/ucb:/bin:/usr/bin";
char *cleanenv[] = { userbuf, homebuf, shellbuf, pathbuf, 0, 0 };
char *shell = "/bin/csh";

char *getenv();

extern char **environ;
struct passwd *pwd;

int main (int argc, char *argv[]) {
  int stat;
  char user [8];

  if ((pwd = getpwuid(getuid())) == NULL) {
      fprintf(stderr, "Who are you?\n");
      exit(1);
  }

  strcpy(user, pwd->pw_name);

  if ((pwd = getpwnam(user)) == NULL) {
      fprintf(stderr, "Unknown login: %s\n", user);
      exit(1);
  }

  stat = skey_haskey (user);

  if (stat == 1) {
     fprintf(stderr,"keysh: no entry for user %s.\n", user);
     exit (-1);
  }

  if (stat == -1) {
     fprintf(stderr, "keysh: could not open key file.\n");
     exit (-1);
  }

  if (skey_authenticate (user) == -1) {
      printf ("Invalid response.\n");
      exit (-1);
  }

  if (setgid(pwd->pw_gid) < 0) {
      perror("keysh: setgid");
      exit(3);
  }

  if (initgroups(user, pwd->pw_gid)) {
      fprintf(stderr, "keysh: initgroups failed\n");
      exit(4);
  }

  if (setuid(pwd->pw_uid) < 0) {
      perror("keysh: setuid");
      exit(5);
  }

  cleanenv[4] = getenv("TERM");
  environ = cleanenv;

  /*setenv("USER", pwd->pw_name, userbuf);
  setenv("SHELL", shell, shellbuf);
  setenv("HOME", pwd->pw_dir, homebuf);
  */
  if (chdir(pwd->pw_dir) < 0) {
      fprintf(stderr, "No directory\n");
      exit(6);
  }

  execv (shell, argv);
  fprintf(stderr, "No shell\n");
  exit(7);
}
/*
int setenv (char *ename, char *eval, char *buf) {
  register char *cp, *dp;
  register char **ep = environ;


   * this assumes an environment variable "ename" already exists

   while (dp = *ep++) {
       for (cp = ename; *cp == *dp && *cp; cp++, dp++)
            continue;
       if (*cp == 0 && (*dp == '=' || *dp == 0)) {
            strcat(buf, eval);
            *--ep = buf;
            return;
       }
   }
}
*/
/*
char *getenv(char *ename) {
  register char *cp, *dp;
  register char **ep = (environ);

  while (dp = *ep++) {
         for (cp = ename; *cp == *dp && *cp; cp++, dp++)
              continue;
         if (*cp == 0 && (*dp == '=' || *dp == 0))
              return (*--ep);
  }
  return ((char *)0);
}*/
