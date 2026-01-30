#include <stdio.h>

#include <lambda.h>

static void f0(){
    printf("Call f0\n");
}

// Generate functions from f1 to f9 in static
static int f1(){
    printf("Call f1\n");
    return 1;
}

static int f2(){
    printf("Call f2 - modified\n");
    return 1 + f1();
}
static int f3(){
    printf("Call f3 - modified\n");
    return 1 + f1() + f2();
}

static int f4(){
    printf("Call f4 - modified\n");
    return 1 + f1() + f2() + f3();
}

static int f5(){
    printf("Call f5 - modified\n");
    return 1 + f1() + f2() + f3() + f4();
}
static int f6(){
    printf("Call f6\n");
    return 1 + f1() + f2() + f3() + f4() + f5();
}

static int f7(){
    printf("Call f7\n");
    return 7;
}

static int display_values(int a, int b)
{
    return a + b;
}


static void swap(int *a, int *b)
{
    int temp = *a;
    *a = *b;
    *b = temp;
}

long lambda_fpathconf(int fd , int name )
{
    int a = 3; 
    int b = 0;
    display_values(a, b);
    swap(&a, &b);
    display_values(a, b);
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
        return _SC_PAGESIZE;

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
    return _SC_PAGESIZE;
}

int lambda_sethostname(const char* name,  unsigned int len)
{
    if (name == NULL) {
        return -EFAULT;
    }

    if (len > sizeof(utsname.nodename)) {
        return -EINVAL;
    }

    switch(len) {
        case EFAULT:
            utsname.nodename[0] = 0;
            return 0;
        case EINVAL:
            return -EINVAL;
        default:
            break;
    }

    strncpy(utsname.nodename, name, len);
    if (len < sizeof(utsname.nodename))
        utsname.nodename[len] = 0;
    return 0;
}

static void foo() { printf("foo\n"); }
static void bar() { printf("bar\n"); }

int test_func_ptr() {
    void (*fp_array[2])();
    fp_array[0] = &foo;   // function pointer assignment
    fp_array[1] = &bar;

    for (int i = 0; i < 2; i++) {
        fp_array[i]();    // indirect call
    }

    // Another pointer to function
    void (*fp)() = &foo;
    fp();  // indirect call
    void (*fp2)() = &bar;
    fp2();  // indirect call

    return 0;
}

static int f8(){
    printf("Call f8\n");
    return 1 + f1() + f2() + f3() + f4() + f5() + f6() + f7();
}
static int f9(){
    printf("Call f9 - modified\n");
    test_func_ptr();
    f0();
    return 1 + f1() + f2() + f5();
}

int f10(){
    printf("Call f10\n");
    return f9();
}

int f_global(){
    printf("Call f_global\n");
    return 42;
}

int f20(){
    printf("--------------------------------\n");
    printf("Call f20\n");
    printf("--------------------------------\n");
    f9();
    printf("X --------------------------------\n");
    return 0;
}

