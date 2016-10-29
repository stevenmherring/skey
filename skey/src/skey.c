/*
 * S/KEY v1.1b (skey.c)
 *
 * Authors:
 *          Neil M. Haller <nmh@thumper.bellcore.com>
 *          Philip R. Karn <karn@chicago.qualcomm.com>
 *          John S. Walden <jsw@thumper.bellcore.com>
 *          Scott Chasin <chasin@crimelab.com>
 *
 *
 * Stand-alone program for computing responses to S/Key challenges.
 * Takes the iteration count and seed as command line args, prompts
 * for the user's key, and produces both word and hex format responses.
 *
 * Usage example:
 *	>skey 88 ka9q2
 *	Enter password:
 *	OMEN US HORN OMIT BACK AHOY
 *	>
 */

#include "md4.h"
#include "skey.h"
#include "debug.h"

//globals
int getopt ();
int optind;
char *optarg;

void usage(char *prog) {
  printf("Usage: %s [OPTIONS [-p password ] [-n count] <sequence #>[/] <key> \n", prog);
  printf("   -p [ARG] :  One time use password.\n");
  printf("   -n [ARG] :  Number of times to apply one time use function.\n");
  printf("   -l [ARG] :  Set the logging device for debugging output from stderr to the file ARG. Fail if cannot append to file ARG.\n");
  printf("   -d       :  Increases debugging level by one, may be used multiple times.\n");
  printf("               Lvl 1 -> Show entry/exit point of every function.\n");
  printf("               Lvl 2 -> In addition to Level 1, will also show return values about to be returned from functions.\n");
  printf("               Lvl 3 -> In addition to level 2, will also show arguments passed to functions.\n");
  printf("   -v       :  To display a version number of the package (stderr, but not exit program).\n");
  printf("   -h       :  To display a help/usage string (then exit program)\n");
}//help

void printVersion() {
  fprintf(stderr, "S/Key Version 1.1b\n");
}//printVersion

//read pass without displaying, ala shut off terminal echo
char *readpass(char* buf, int n);
void sevenbit(char* s);


int main(int argc, char *argv[]){
  int n, cnt, i, pass = 0;
  int logging = 0;
  int dLevel = 0;
  char passwd[256], key[8], buf[33], *seed, *slash;
  //char *debug;
  //int dMallocMax = 256;
  //char logFile[256]; //256 def size for file name
  //int kc;

  cnt = 1;

  while ((i = getopt (argc, argv, "hvdn:p:l")) != EOF)
  {
    switch (i)
    {
    case 'n':
      cnt = atoi (optarg);
      break;
    case 'p':
      strcpy (passwd, optarg);
      pass = 1;
      break;
    case 'h':
      usage(argv[0]); //print help, use program name
      exit(0);
    case 'v':
      printVersion();
      //exit(0); //don't exit
      break;
    case 'd':
      dLevel++;
      break;
    case 'l':
      logging = 1;
      strcpy(logFile, optarg);
      break;
    }
  }
  //check for logging first
  if(logging) {
    fprintf(stderr, "Debug routed to file %s.\n", logFile);
  }//logging

  /* could be in the form <number>/<seed> */

  if (argc <= optind + 1)
  {
    /* look for / in it */
    if (argc <= optind)
    {
      usage (argv[0]);
      exit (1);
    }
    slash = strchr (argv[optind], '/');
    if (slash == NULL)
    {
      usage (argv[0]);
      exit (1);
    }
    *slash++ = '\0';
    seed = slash;

    if ((n = atoi(argv[optind])) < 0)
    {
      printf ("%s not positive\n", argv[optind]);
      usage (argv[0]);
      exit (1);
    }
  }
  else
  {

    if (n < 0)
    {
      printf ("%s not positive\n", argv[optind]);
      usage (argv[0]);
      exit (1);
    }
    seed = argv[++optind];
  }

  /* Get user's secret password */
  if (!pass)
  {
    printf ("Enter secret password: ");
    readpass (passwd, sizeof (passwd));
  }
  rip (passwd);

  /* Crunch seed and password into starting key */
  if ((keycrunch (key, seed, passwd)) != 0)
  {
    fprintf (stderr, "%s: key crunch failed\n", argv[0]);
    exit (1);
  }
  if (cnt == 1)
  {
    while (n-- != 0)
      f (key);
    printf ("%s\n", btoe (buf, key));
#ifdef	HEXIN
    printf ("%s\n", put8 (buf, key));
#endif
   }
  else
  {
    for (i = 0; i <= n - cnt; i++)
      f (key);
    for (; i <= n; i++)
    {
#ifdef	HEXIN
      printf ("%d: %-29s  %s\n", i, btoe (buf, key), put8 (buf, key));
#else
      printf ("%d: %-29s\n", i, btoe (buf, key));
#endif
      f (key);
    }
  }
  exit (0);
}
