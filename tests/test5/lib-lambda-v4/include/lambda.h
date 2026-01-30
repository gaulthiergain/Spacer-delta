#ifndef LIBLAMBDA
#define LIBLAMBDA

int lambda_getpagesize(void);
int lambda_confstr(int name , char *buf, long unsigned int len );
int lambda_uname(void * buf);
int lambda_sethostname(const char* name, long unsigned int len);
long lambda_sysconf(int name);
long lambda_pathconf(const char *path , int name );
long lambda_fpathconf(int fd, int name );

#endif