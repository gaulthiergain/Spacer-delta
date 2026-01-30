#ifndef LIBLAMBDA
#define LIBLAMBDA

#include <stddef.h>
#include <uk/arch/limits.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <uk/essentials.h>
#include <uk/config.h>
#include <stdio.h>

#if CONFIG_LIBVFSCORE
/* For FDTABLE_MAX_FILES. */
#include <vfscore/file.h>
#endif

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
};

static struct utsname_lambda utsname = {
    .sysname    = "Unikraft",
    .nodename   = "unikraft",
    /* glibc looks into the release field to check the kernel version:
     * We prepend '5-' in order to be "new enough" for it.
     */
    .release    = "5-" STRINGIFY(UK_CODENAME),
    .version    = STRINGIFY(UK_FULLVERSION),
    .machine    = "x86_64"
};

int lambda_getpagesize(void);
int lambda_confstr(int name , char *buf,  unsigned int len );
int lambda_sethostname(const char* name,  unsigned int len);
long lambda_sysconf(int name);
long lambda_pathconf(const char *path , int name );
long lambda_fpathconf(int fd, int name );

#endif