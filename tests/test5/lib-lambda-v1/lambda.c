#include <lambda.h>

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

int lambda_confstr(int name , char *buf ,   unsigned int len)
{
    printf("lambda_confstr\n");
    printf("name: %d\n", name);
    printf("buf: %s\n", buf);
    printf("len: %ld\n", len);
    return 0;
}

int lambda_getpagesize(void)
{
    return __PAGE_SIZE;
}

int lambda_sethostname(const char* name,  unsigned int len)
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
