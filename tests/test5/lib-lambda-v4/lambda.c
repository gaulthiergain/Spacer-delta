#include <stddef.h>
#include <uk/arch/limits.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <uk/essentials.h>
#include <uk/config.h>
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
};

#if CONFIG_LIBVFSCORE
/* For FDTABLE_MAX_FILES. */
#include <vfscore/file.h>
#endif

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

long lambda_fpathconf(int fd , int name )
{
    printf("lambda_confstr\n");
    printf("name: %d\n", name);
    printf("fd: %d\n", fd);
    return 0;
}

long lambda_pathconf(const char *path , int name )
{
    printf("lambda_confstr\n");
    printf("name: %d\n", name);
    printf("path: %s\n", path);
    return 0;
}

long lambda_sysconf(int name)
{
    if (name == _SC_NPROCESSORS_ONLN)
        return 1;

    if (name == _SC_PAGESIZE)
        return __PAGE_SIZE;

#if CONFIG_LIBVFSCORE
    if (name == _SC_OPEN_MAX)
        return FDTABLE_MAX_FILES;
#endif

    return 0;
}

int lambda_confstr(int name , char *buf , int len )
{
    printf("lambda_confstr\n");
    printf("name: %d\n", name);
    printf("buf: %s\n", buf);
    printf("len: %d\n", len);
    return 0;
}

int lambda_getpagesize(void)
{
    return __PAGE_SIZE;
}

int lambda_uname(void * buf)
{
    if (buf == NULL)
        return -EFAULT;

    memcpy(buf, &utsname, sizeof(struct utsname_lambda));
    return 0;
}

int lambda_sethostname(const char* name, long unsigned int len)
{
    if (name == NULL) {
        return -EFAULT;
    }

    if (len > sizeof(utsname.nodename)) {
        return -EINVAL;
    }

    strncpy(utsname.nodename, name, len);
    if (len < sizeof(utsname.nodename))
        utsname.nodename[len] = 0;
    return 0;
}
