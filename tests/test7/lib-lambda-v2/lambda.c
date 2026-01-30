#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include <stdio.h>

#define ENOTBLK   15  /* Block device required */
#define ESOCKTNOSUPPORT 44  /* Socket type not supported */
#define ESHUTDOWN 58  /* Cannot send after transport endpoint shutdown */
#define EPROCLIM        670      /* SUNOS: Too many processes */
#define EUSERS    68  /* Too many users */
#define EBADRPC   991
#define ERPCMISMATCH 1001
#define EPROGUNAVAIL 1011
#define EPROGMISMATCH 1021
#define EPROCUNAVAIL 1031
#define EAUTH 1041
#define ENEEDAUTH 1051
#define ENOATTR 1111
#define EDOOFUS 1071
#define ENOTCAPABLE 1081
#define ECAPMODE 1091

#ifndef EFTYPE
#define EFTYPE 1061
#endif

void *lambda_memcpy(void *dst, const void *src, size_t len)
{
    size_t p;

    for (p = 0; p < len; ++p)
        *((unsigned char *)(((uintptr_t)dst) + p)) = *((unsigned char *)(((uintptr_t)src) + p));

    return dst;
}

void *lambda_memset(void *ptr, int val, size_t len)
{
    unsigned char *p = (unsigned char *) ptr;

    for (; len > 0; --len)
        *(p++) = (unsigned char)val;

    return ptr;
}

void *lambda_memchr(const void *ptr, int val, size_t len)
{
    uintptr_t o = 0;

    for (o = 0; o < (uintptr_t)len; ++o)
        if (*((const uint8_t *)(((uintptr_t)ptr) + o)) == (uint8_t)val)
            return (void *)((uintptr_t)ptr + o);

    return NULL; /* did not find val */
}

void *lambda_memrchr(const void *m, int c, size_t n)
{
    const unsigned char *s = m;

    c = (unsigned char) c;
    while (n--)
        if (s[n] == c)
            return (void *) (s + n);
    return 0;
}

int lambda_memcmp(const void *ptr1, const void *ptr2, size_t len)
{
    const unsigned char *c1 = (const unsigned char *)ptr1;
    const unsigned char *c2 = (const unsigned char *)ptr2;

    for (; len > 0; --len, ++c1, ++c2) {
        if ((*c1) != (*c2))
            return ((*c1) - (*c2));
    }

    return 0;
}

size_t lambda_strlen(const char *str)
{
    return strnlen(str, SIZE_MAX);
}

size_t lambda_strnlen(const char *str, size_t len)
{
    const char *p = memchr(str, 0, len);
    return p ? (size_t) (p - str) : len;
}

char *lambda_strncpy(char *dst, const char *src, size_t len)
{
    size_t clen;

    clen = strnlen(src, len);
    memcpy(dst, src, clen);

    /* instead of filling up the rest of left space with zeros,
     * append a termination character if we did not copy one
     */
    if (clen < len && dst[clen - 1] != '\0')
        dst[clen] = '\0';
    return dst;
}

int lambda_strncmp(const char *str1, const char *str2, size_t len)
{
    const char *c1 = (const char *)str1;
    const char *c2 = (const char *)str2;

    for (; len > 0; --len, ++c1, ++c2) {
        if ((*c1) != (*c2))
            return (int)((*c1) - (*c2));
        if ((*c1) == '\0')
            break;
    }
    return 0;
}

int lambda_strcmp(const char *str1, const char *str2)
{
    register signed char __res;

    while ((__res = *str1 - *str2++) == 0 && *str1++)
        ;

    return __res;
}

/* The following code is taken from musl libc */
#define ALIGN (sizeof(size_t))
#define ONES ((size_t) -1 / UCHAR_MAX)
#define HIGHS (ONES * (UCHAR_MAX / 2 + 1))
#define HASZERO(x) (((x) - ONES) & ~(x) & HIGHS)
#define BITOP(a, b, op) \
        ((a)[(size_t)(b) / (8*sizeof *(a))] op \
        (size_t)1 << ((size_t)(b) % (8 * sizeof *(a))))

char *lambda_strchrnul(const char *s, int c)
{
    size_t *w, k;

    c = (unsigned char)c;
    if (!c)
        return (char *)s + strlen(s);

    for (; (uintptr_t)s % ALIGN; s++)
        if (!*s || *(unsigned char *)s == c)
            return (char *)s;
    k = ONES * c;
    for (w = (void *)s; !HASZERO(*w) && !HASZERO(*w ^ k); w++)
        ;
    for (s = (void *)w; *s && *(unsigned char *)s != c; s++)
        ;
    return (char *)s;
}

char *lambda_strchr(const char *str, int c)
{
    char *r = lambda_strchrnul(str, c);
    return *(unsigned char *)r == (unsigned char)c ? r : 0;
}

char *lambda_strrchr(const char *s, int c)
{
    return lambda_memrchr(s, c, strlen(s) + 1);
}

size_t lambda_strcspn(const char *s, const char *c)
{
    const char *a = s;
    size_t byteset[32 / sizeof(size_t)];

    if (!c[0] || !c[1])
        return lambda_strchrnul(s, *c)-a;

    memset(byteset, 0, sizeof(byteset));
    for (; *c && BITOP(byteset, *(unsigned char *)c, |=); c++)
        ;
    for (; *s && !BITOP(byteset, *(unsigned char *)s, &); s++)
        ;
    return s-a;
}

size_t lambda_strspn(const char *s, const char *c)
{
    const char *a = s;
    size_t byteset[32 / sizeof(size_t)] = { 0 };

    if (!c[0])
        return 0;
    if (!c[1]) {
        for (; *s == *c; s++)
            ;
        return s-a;
    }

    for (; *c && BITOP(byteset, *(unsigned char *)c, |=); c++)
        ;
    for (; *s && BITOP(byteset, *(unsigned char *)s, &); s++)
        ;
    return s-a;
}

char *lambda_strtok(char *restrict s, const char *restrict sep)
{
    static char *p;

    if (!s && !(s = p))
        return NULL;
    s += strspn(s, sep);
    if (!*s)
        return p = 0;
    p = s + strcspn(s, sep);
    if (*p)
        *p++ = 0;
    else
        p = 0;
    return s;
}

char *lambda_strtok_r(char *restrict s, const char *restrict sep, char **restrict p)
{
    if (!s && !(s = *p))
        return NULL;
    s += strspn(s, sep);
    if (!*s)
        return *p = 0;
    *p = s + strcspn(s, sep);
    if (**p)
        *(*p)++ = 0;
    else
        *p = 0;
    return s;
}

char *lambda_strndup(const char *str, size_t len)
{
    char *__res;
    int __len;

    __len = strnlen(str, len);

    __res = malloc(__len + 1);
    if (__res) {
        memcpy(__res, str, __len);
        __res[__len] = '\0';
    }

    return __res;
}

char *lambda_strdup(const char *str)
{
    return strndup(str, SIZE_MAX);
}

/* strlcpy has different ALIGN */
#undef ALIGN
#define ALIGN (sizeof(size_t)-1)
size_t lambda_strlcpy(char *d, const char *s, size_t n)
{
    char *d0 = d;
    size_t *wd;
    const size_t *ws;

    if (!n--)
        goto finish;

    if (((uintptr_t)s & ALIGN) == ((uintptr_t)d & ALIGN)) {
        for (; ((uintptr_t) s & ALIGN) && n && (*d = *s);
             n--, s++, d++)
            ;

        if (n && *s) {
            wd = (void *)d; ws = (const void *)s;
            for (; n >= sizeof(size_t) && !HASZERO(*ws);
                 n -= sizeof(size_t), ws++, wd++)
                *wd = *ws;

            d = (void *)wd; s = (const void *)ws;
        }
    }

    for (; n && (*d = *s); n--, s++, d++)
        ;
    *d = 0;
finish:
    return d-d0 + strlen(s);
}

/* GNU-specific version of strerror_r */
char *lambda_strerror_r(int errnum, char *buf, size_t buflen)
{
    const char *strerr;

    switch (errnum) {
    case EPERM:
        strerr = "Operation not permitted";
        break;
    case ENOENT:
        strerr = "No such file or directory";
        break;
    case ESRCH:
        strerr = "No such process";
        break;
    case EINTR:
        strerr = "Interrupted system call";
        break;
    case EIO:
        strerr = "Input/output error";
        break;
    case ENXIO:
        strerr = "Device not configured";
        break;
    case E2BIG:
        strerr = "Argument list too long";
        break;
    case ENOEXEC:
        strerr = "Exec format error";
        break;
    case EBADF:
        strerr = "Bad file descriptor";
        break;
    case ECHILD:
        strerr = "No child processes";
        break;
    case EDEADLK:
        strerr = "Resource deadlock avoided";
        break;
    case ENOMEM:
        strerr = "Cannot allocate memory";
        break;
    case EACCES:
        strerr = "Permission denied";
        break;
    case EFAULT:
        strerr = "Bad address";
        break;
    case ENOTBLK:
        strerr = "Block device required";
        break;
    case EBUSY:
        strerr = "Device busy";
        break;
    case EEXIST:
        strerr = "File exists";
        break;
    case EXDEV:
        strerr = "Cross-device link";
        break;
    case ENODEV:
        strerr = "Operation not supported by device";
        break;
    case ENOTDIR:
        strerr = "Not a directory";
        break;
    case EISDIR:
        strerr = "Is a directory";
        break;
    case EINVAL:
        strerr = "Invalid argument";
        break;
    case ENFILE:
        strerr = "Too many open files in system";
        break;
    case EMFILE:
        strerr = "Too many open files";
        break;
    case ENOTTY:
        strerr = "Inappropriate ioctl for device";
        break;
    case ETXTBSY:
        strerr = "Text file busy";
        break;
    case EFBIG:
        strerr = "File too large";
        break;
    case ENOSPC:
        strerr = "No space left on device";
        break;
    case ESPIPE:
        strerr = "Illegal seek";
        break;
    case EROFS:
        strerr = "Read-only file system";
        break;
    case EMLINK:
        strerr = "Too many links";
        break;
    case EPIPE:
        strerr = "Broken pipe";
        break;
    case EDOM:
        strerr = "Numerical argument out of domain";
        break;
    case ERANGE:
        strerr = "Result too large";
        break;
    case EAGAIN:
        strerr = "Resource temporarily unavailable";
        break;
    case EINPROGRESS:
        strerr = "Operation now in progress";
        break;
    case EALREADY:
        strerr = "Operation already in progress";
        break;
    case ENOTSOCK:
        strerr = "Socket operation on non-socket";
        break;
    case EDESTADDRREQ:
        strerr = "Destination address required";
        break;
    case EMSGSIZE:
        strerr = "Message too long";
        break;
    case EPROTOTYPE:
        strerr = "Protocol wrong type for socket";
        break;
    case ENOPROTOOPT:
        strerr = "Protocol not available";
        break;
    case EPROTONOSUPPORT:
        strerr = "Protocol not supported";
        break;
    case ESOCKTNOSUPPORT:
        strerr = "Socket type not supported";
        break;
    case EOPNOTSUPP:
        strerr = "Operation not supported on socket";
        break;
    case EPFNOSUPPORT:
        strerr = "Protocol family not supported";
        break;
    case EAFNOSUPPORT:
        strerr = "Address family not supported by protocol family";
        break;
    case EADDRINUSE:
        strerr = "Address already in use";
        break;
    case EADDRNOTAVAIL:
        strerr = "Can't assign requested address";
        break;
    case ENETDOWN:
        strerr = "Network is down";
        break;
    case ENETUNREACH:
        strerr = "Network is unreachable";
        break;
    case ENETRESET:
        strerr = "Network dropped connection on reset";
        break;
    case ECONNABORTED:
        strerr = "Software caused connection abort";
        break;
    case ECONNRESET:
        strerr = "Connection reset by peer";
        break;
    case ENOBUFS:
        strerr = "No buffer space available";
        break;
    case EISCONN:
        strerr = "Socket is already connected";
        break;
    case ENOTCONN:
        strerr = "Socket is not connected";
        break;
    case ESHUTDOWN:
        strerr = "Can't send after socket shutdown";
        break;
    case ETIMEDOUT:
        strerr = "Operation timed out";
        break;
    case ECONNREFUSED:
        strerr = "Connection refused";
        break;
    case ELOOP:
        strerr = "Too many levels of symbolic links";
        break;
    case ENAMETOOLONG:
        strerr = "File name too long";
        break;
    case EHOSTDOWN:
        strerr = "Host is down";
        break;
    case EHOSTUNREACH:
        strerr = "No route to host";
        break;
    case ENOTEMPTY:
        strerr = "Directory not empty";
        break;
    case EPROCLIM:
        strerr = "Too many processes";
        break;
    case EUSERS:
        strerr = "Too many users";
        break;
    case EDQUOT:
        strerr = "Disc quota exceeded";
        break;
    case ESTALE:
        strerr = "Stale NFS file handle";
        break;
    case EBADRPC:
        strerr = "RPC struct is bad";
        break;
    case ERPCMISMATCH:
        strerr = "RPC version wrong";
        break;
    case EPROGUNAVAIL:
        strerr = "RPC prog";
        break;
    case EPROGMISMATCH:
        strerr = "Program version wrong";
        break;
    case EPROCUNAVAIL:
        strerr = "Bad procedure for program";
        break;
    case ENOLCK:
        strerr = "No locks available";
        break;
    case ENOSYS:
        strerr = "Function not implemented";
        break;
    case EFTYPE:
        strerr = "Inappropriate file type or format";
        break;
    case EAUTH:
        strerr = "Authentication error";
        break;
    case ENEEDAUTH:
        strerr = "Need authenticator";
        break;
    case EIDRM:
        strerr = "Identifier removed";
        break;
    case ENOMSG:
        strerr = "No message of desired type";
        break;
    case EOVERFLOW:
        strerr = "Value too large to be stored in data type";
        break;
    case ECANCELED:
        strerr = "Operation canceled";
        break;
    case EILSEQ:
        strerr = "Illegal byte sequence";
        break;
    case ENOATTR:
        strerr = "Attribute not found";
        break;
    case EDOOFUS:
        strerr = "Programming error";
        break;
    case EBADMSG:
        strerr = "Bad message";
        break;
    case EMULTIHOP:
        strerr = "Multihop attempted";
        break;
    case ENOLINK:
        strerr = "Link has been severed";
        break;
    case EPROTO:
        strerr = "Protocol error";
        break;
    case ENOTCAPABLE:
        strerr = "Capabilities insufficient";
        break;
    case ECAPMODE:
        strerr = "Not permitted in capability mode";
        break;
    case ENOTRECOVERABLE:
        strerr = "State not recoverable";
        break;
    case EOWNERDEAD:
        strerr = "Previous owner died";
        break;
    default:
        strerr = NULL;
        errno = EINVAL; /* Unknown errnum requires errno to be set */
        break;
    }

    if (!buflen)
        return buf;

    /*
     * NOTE: If target buffer is too small, we are supposed to set
     *       errno to ERANGE. We ignore this case for simplification.
     */
    if (strerr)
        strncpy(buf, strerr, buflen);
    else
        snprintf(buf, buflen, "Unknown error %d", errnum);

    /* ensure null termination */
    buf[buflen - 1] = '\0';
    return buf;
}

/* NOTE: strerror() is not thread-safe, nor reentrant-safe */
char *lambda_strerror(int errnum)
{
    /* NOTE: Our longest message is currently 48 characters. With
     *       64 characters we should have room for minor changes
     *       in the future.
     */
    static char buf[64];

    return strerror_r(errnum, buf, sizeof(buf));
}

char *lambda_strncat(char *dest, const char *src, size_t n)
{
    char *a = dest;

    dest = dest + strlen(dest);

    if (src != NULL) {
        while (n && *src) {
            n--;
            *dest++ = *src++;
        }
    }

    *dest++ = 0;
    return a;
}
