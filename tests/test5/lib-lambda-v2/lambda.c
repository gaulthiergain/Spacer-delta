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

int lambda_confstr(int name , char *buf , int len )
{
    printf("lambda_confstr\n");
    printf("name: %d\n", name);
    printf("buf: %s\n", buf);
    printf("len: %ld\n", len);
    return 0;
}

int lambda_uname(void * buf)
{
    if (buf == NULL)
        return -EFAULT;

    memcpy(buf, &utsname, sizeof(struct utsname_lambda));
    return 0;
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

int lambda_gethostname(char *name, int len)
{
    struct utsname_lambda buf;
    int node_len;
    int rc;

    rc = lambda_uname(&buf);
    if (rc)
        return -1;

    node_len = strlen(buf.nodename) + 1;
    if (node_len > len) {
        errno = ENAMETOOLONG;
        return -1;
    }

    strncpy(name, buf.nodename, len);

    return 0;
}