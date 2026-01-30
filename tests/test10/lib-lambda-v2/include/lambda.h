#ifndef LIBLAMBDA
#define LIBLAMBDA

#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>

#define __UTSNAMELEN 65	/* synchronize with kernel */
#define _SC_PAGESIZE 1
#define _SC_NPROCESSORS_ONLN 2
struct utsname_lambda {
	char sysname[__UTSNAMELEN];
	char nodename[__UTSNAMELEN];
	char release[__UTSNAMELEN];
	char version[__UTSNAMELEN];
	char machine[__UTSNAMELEN];
	char domainname[__UTSNAMELEN];
    char padding[24]; // Padding to make the struct size 512 bytes
    char unused[448]; // Unused space
};

static struct utsname_lambda utsname = {
    .sysname    = "Unikraft - lambda",
    .nodename   = "unikraft - module",
    /* glibc looks into the release field to check the kernel version:
     * We prepend '5-' in order to be "new enough" for it.
     */
    .release    = "5-",
    .version    = "TEST_VERSION",
    .machine    = "x86_64_v2",
    .domainname = "localdomain",
    .padding    = {0},
    .unused     = {0}
};

int lambda_getpagesize(void);
int lambda_confstr(int name , char *buf,  unsigned int len );
int lambda_sethostname(const char* name,  unsigned int len);
long lambda_sysconf(int name);
long lambda_pathconf(const char *path , int name );
long lambda_fpathconf(int fd, int name );
int f10();
int f20();

#endif