#ifndef LIBLAMBDA
#define LIBLAMBDA
#include <stddef.h>

void *lambda_memcpy(void *dst, const void *src, size_t len);
void *lambda_memset(void *ptr, int val, size_t len);
void *lambda_memchr(const void *ptr, int val, size_t len);
void *lambda_memrchr(const void *m, int c, size_t n);
void *lambda_memmove(void *dst, const void *src, size_t len);
int lambda_memcmp(const void *ptr1, const void *ptr2, size_t len);
size_t lambda_strlen(const char *str);
size_t lambda_strnlen(const char *str, size_t len);
char *lambda_strncpy(char *dst, const char *src, size_t len);
char *lambda_strcpy(char *dst, const char *src);
int lambda_strncmp(const char *str1, const char *str2, size_t len);
int lambda_strcmp(const char *str1, const char *str2);
char *lambda_strchrnul(const char *s, int c);
char *lambda_strchr(const char *str, int c);
char *lambda_strrchr(const char *s, int c);
size_t lambda_strcspn(const char *s, const char *c);
size_t lambda_strspn(const char *s, const char *c);
char *lambda_strtok(char *restrict s, const char *restrict sep);
char *lambda_strtok_r(char *restrict s, const char *restrict sep, char **restrict p);
char *lambda_strndup(const char *str, size_t len);
char *lambda_strdup(const char *str);
size_t lambda_strlcpy(char *d, const char *s, size_t n);
size_t lambda_strlcat(char *d, const char *s, size_t n);
char *lambda_strerror_r(int errnum, char *buf, size_t buflen);
char *lambda_strerror(int errnum);
char *lambda_strncat(char *dest, const char *src, size_t n);

#endif