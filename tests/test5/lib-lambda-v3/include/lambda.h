#ifndef LIBLAMBDA
#define LIBLAMBDA


#define _SC_PAGESIZE 1
#define _SC_NPROCESSORS_ONLN 2

int lambda_gethostname(char *name,  unsigned int len);
int lambda_getpagesize(void);
int lambda_confstr(int name , char *buf,  unsigned int len );
int lambda_uname(void * buf);
long lambda_sysconf(int name);
long lambda_pathconf(const char *path , int name );
long lambda_fpathconf(int fd, int name );

#endif