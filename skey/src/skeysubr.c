/* S/KEY v1.1b (skeysubr.c)
 *
 * Authors:
 *          Neil M. Haller <nmh@thumper.bellcore.com>
 *          Philip R. Karn <karn@chicago.qualcomm.com>
 *          John S. Walden <jsw@thumper.bellcore.com>
 *
 * Modifications:
 *          Scott Chasin <chasin@crimelab.com>
 *
 * S/KEY misc routines.
 */

#include <stdio.h>
#include "md4.h"
#include "skey.h"
#include "debug.h"

#ifdef __STDLIB__
#include <stdlib.h>
#endif

#ifdef __IOCTL__
#include <ioctl.h>
#endif

#ifdef __SYSIOCTL__
#include <sys/ioctl.h>
#endif

#ifdef __TERMIO__
#include <termio.h>
#define TTYSTRUCT termio
#define stty(fd,buf) ioctl((fd),TCSETA,(buf)) //tcsetattr
#define gtty(fd,buf) ioctl((fd),TCGETA,(buf)) //tcgetatt
struct termio newtty;
struct termio oldtty;
#endif

#ifdef __TERMIOS__
#ifndef __TERMIO__
#include <termios.h>
#define TTYSTRUCT termios
struct termios newtty;
struct termios oldtty;
#define stty(fd,buf) tcsetattr((fd), TCSAFLUSH, buf)
#define gtty(fd,buf) tcgetattr((fd), buf)
#endif
#endif

#ifdef __SGTTY__
#ifndef __TERMIO__
#ifndef __TERMIOS__
#include <sgtty.h>
#define TTYSTRUCT sgttyb
#define stty(fd,buf) ioctl((fd),TIOCSETN,(buf))
#define gtty(fd,buf) ioctl((fd),TIOCGETP,(buf))
struct sgttyb newtty;
struct sgttyb oldtty;
struct tchars chars;
#endif
#endif
#endif

#ifdef __SYSTYPES__
#include <sys/types.h>
#endif

#ifdef __STRING__
#include <string.h>
#endif

#ifdef __SIGNAL__
#include <signal.h>
#endif

#ifdef	__MSDOS__
#include <dos.h>
#endif

#ifdef SIGVOID
#define SIGTYPE void
#else
#define SIGTYPE void
#endif

SIGTYPE trapped();

#if (defined(__MSDOS__) || defined(MPU8086) || defined(MPU8080) \
    || defined(vax) || defined (MIPSEL))
#define	LITTLE_ENDIAN
#endif

int keycrunch(char *result, char *seed, char *passwd);
void f (char *x);
char *readpass (char *buf, int n);
void rip (char *buf);
void set_term ();
void echo_off ();
void backspace(char *buf);
void seventbit(char *s);
void trapped();
void unset_term();


/* Crunch a key:
 * concatenate the seed and the password, run through MD4 and
 * collapse to 64 bits. This is defined as the user's starting key.
 */
int keycrunch(char *result, char *seed, char *passwd)
{
	char *buf;
	MDstruct md;
	unsigned int buflen;
#ifndef	__LITTLE__ENDIAN__
	int i;
	register long tmp;
#endif

	buflen = strlen(seed) + strlen(passwd);
	if ((buf = (char *)malloc(buflen+1)) == NULL)
		return -1;
	strcpy(buf,seed);
	strcat(buf,passwd);

	/* Crunch the key through MD4 */
	sevenbit(buf);
	MDbegin(&md);
	MDupdate(&md,(unsigned char *)buf,8*buflen);

	free(buf);

	/* Fold result from 128 to 64 bits */
	md.buffer[0] ^= md.buffer[2];
	md.buffer[1] ^= md.buffer[3];

#ifdef	__LITTLE__ENDIAN__
	/* Only works on byte-addressed little-endian machines!! */
	memcpy(result,(char *)md.buffer,8);
#else
	/* Default (but slow) code that will convert to
	 * little-endian byte ordering on any machine
	 */
	for (i=0; i<2; i++) {
		tmp = md.buffer[i];
		*result++ = tmp;
		tmp >>= 8;
		*result++ = tmp;
		tmp >>= 8;
		*result++ = tmp;
		tmp >>= 8;
		*result++ = tmp;
	}
#endif

	return 0;
}

/* The one-way function f(). Takes 8 bytes and returns 8 bytes in place */
void f (char *x) {
	MDstruct md;
#ifndef	__LITTLE__ENDIAN__
	register long tmp;
#endif

	MDbegin(&md);
	MDupdate(&md,(unsigned char *)x,64);

	/* Fold 128 to 64 bits */
	md.buffer[0] ^= md.buffer[2];
	md.buffer[1] ^= md.buffer[3];

#ifdef	__LITTLE__ENDIAN__
	/* Only works on byte-addressed little-endian machines!! */
	memcpy(x,(char *)md.buffer,8);

#else
	/* Default (but slow) code that will convert to
	 * little-endian byte ordering on any machine
	 */
	tmp = md.buffer[0];
	*x++ = tmp;
	tmp >>= 8;
	*x++ = tmp;
	tmp >>= 8;
	*x++ = tmp;
	tmp >>= 8;
	*x++ = tmp;

	tmp = md.buffer[1];
	*x++ = tmp;
	tmp >>= 8;
	*x++ = tmp;
	tmp >>= 8;
	*x++ = tmp;
	tmp >>= 8;
	*x = tmp;
#endif
}

/* Strip trailing cr/lf from a line of text */
void rip (char *buf) {
  _d_enter_func(logFile,1,"RIP",buf);
	char *cp;

	if((cp = strchr(buf,'\r')) != NULL)
		*cp = '\0';

	if((cp = strchr(buf,'\n')) != NULL)
		*cp = '\0';
  _d_exit_func(logFile,buf,0);
}

#ifdef	__MSDOS__
char *readpass(char *buf, int n)
{
  int i;
  char *cp;

  for (cp=buf,i = 0; i < n ; i++)
       if ((*cp++ = bdos(7,0,0)) == '\r')
          break;
   *cp = '\0';
   putchar('\n');
   rip(buf);
   return buf;
}
#else

char *readpass (char *buf, int n)
{
    _d_enter_func(logFile,2,"READPASS",buf,n);
    set_term ();
    echo_off ();

    fgets (buf, n, stdin);

    rip (buf);

    printf ("\n\n");
    sevenbit (buf);

    unset_term ();
    _d_exit_func(logFile,buf,0);
    return buf;
}

void set_term ()
{
    #ifndef __TERMIOS__
    gtty (fileno(stdin), &newtty);
    gtty (fileno(stdin), &oldtty);
    #endif

    #ifdef __TERMIOS__
    #ifndef __TERMIO__
    gtty (fileno(stdin), &newtty);
    gtty (fileno(stdin), &oldtty);
    #endif
    #endif
    signal (SIGINT, trapped);
}

void echo_off ()
{
#ifdef __TERMIOS__
      newtty.c_lflag &= ~(ICANON | ECHO | ECHONL);
      newtty.c_cc[VMIN] = 1;
      newtty.c_cc[VTIME] = 0;
      newtty.c_cc[VINTR] = 3;
#endif
#ifdef __TERMIO__
    newtty.c_lflag &= ~(ICANON | ECHO | ECHONL);
#else
  #ifdef __SGTTY__
    newtty.sg_flags |= CBREAK;
    newtty.sg_flags &= ~ECHO;
  #endif
#endif

#ifdef __TERMIO__
    newtty.c_cc[VMIN] = 1;
    newtty.c_cc[VTIME] = 0;
    newtty.c_cc[VINTR] = 3;
#else
  #ifdef __TERMIOS__
    //tcgetattr(fileno(stdin), &oldtty);
    tcsetattr(fileno(stdin), TCSAFLUSH, &newtty);
  #else
    ioctl(fileno(stdin), TIOCGETC, &chars);
    chars.t_intrc = 3;
    ioctl(fileno(stdin), TIOCSETC, &chars);
  #endif
#endif

  //  stty (fileno (stdin), &newtty); // @TODO: stty gtty
}

void unset_term ()
{
    stty (fileno (stdin), &oldtty);

#ifndef __SGTTY__
#ifndef __TERMIOS__
    ioctl(fileno(stdin), TIOCSETC, &chars);
#endif
#endif
}

void trapped()
 {
  signal (SIGINT, trapped);
  printf ("^C\n");
  unset_term ();
  exit (-1);
 }

#endif

/* removebackspaced over charaters from the string */
void backspace(char *buf) {
  _d_enter_func(logFile,1,"BACKSPACE",buf);
	char bs = 0x8;
	char *cp = buf;
	char *out = buf;

	while(*cp){
		if( *cp == bs ) {
			if(out == buf){
				cp++;
				continue;
			}
			else {
			  cp++;
			  out--;
			}
		}
		else {
			*out++ = *cp++;
		}

	}
	*out = '\0';
  _d_exit_func(logFile, "NO RETURN", 0);
}

/* sevenbit ()
 *
 * Make sure line is all seven bits.
 */

void sevenbit (char *s) {
  _d_enter_func(logFile,1,"SEVENBIT",s);
   while (*s) {
     *s = 0x7f & ( *s);
     s++;
   }
   _d_exit_func(logFile, s, 0);
}
