/*
 * S/KEY v1.1b (skey.h)
 *
 * Authors:
 *          Neil M. Haller <nmh@thumper.bellcore.com>
 *          Philip R. Karn <karn@chicago.qualcomm.com>
 *          John S. Walden <jsw@thumper.bellcore.com>
 *
 * Modifications:
 *          Scott Chasin <chasin@crimelab.com>
 *
 * Main client header
 */
/*
#if	defined(__TURBOC__) || defined(__STDC__) || defined(LATTICE)
#define	ANSIPROTO	1
#endif

#ifndef	__ARGS
#ifdef	ANSIPROTO
#define	__ARGS(x)	x
#else
#define	__ARGS(x)	()
#endif
#endif

#ifdef SOLARIS
#define setpriority(x,y,z)      z
#endif
*/
#include "config.h"
#include <stdarg.h>
#include "debug.h"

#ifdef __STDIO__
#include <stdio.h>
#endif

#ifdef __STDLIB__
#include <stdlib.h>
#endif

#ifdef __STRING__
#include <string.h>
#endif

#ifdef __SGTTY__
#include <sgtty.h>
#endif

#ifdef __SYSTYPES__
#include <sys/types.h>
#endif

#ifdef __FCNTL__
#include <fcntl.h>
#endif

/* Server-side data structure for reading keys file during login */
struct skey {
  FILE *keyfile;
  char buf[256];
  char *logname;
  int n;
  char *seed;
  char *val;
  long recstart;		/* needed so reread of buffer is efficient */
};

/* Client-side structure for scanning data stream for challenge */
struct mc
{
  char buf[256];
  int skip;
  int cnt;
};

char logFile[256];
int dLevel;
void f (char *x);
int keycrunch (char *result, char *seed, char *passwd);
char *btoe (char *engout, char *c);
char *put8 (char *out, char *s);
int etob (char *out, char *e);
void rip (char *buf);
int skeychallenge (struct skey * mp, char *name, char *ss);
int skeylookup (struct skey * mp, char *name);
int skeyverify (struct skey * mp, char *response);
char* readpass(char* buf, int n);
void sevenbit(char* s);
int htoi(register char c);
void backspace(char *buf);
int atob8(register char *out, register char *in);
int btoa8(register char *out, register char *in);
int skey_haskey (char *username);
int skey_authenticate (char *username);
