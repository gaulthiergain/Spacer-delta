#include <stdio.h>
#include <stdlib.h>
#include <lambda.h>
#include <time.h>

int main_lambda(int argc, char *argv[])
{
    // Test de lambda_fpathconf
    lambda_fpathconf(1, _SC_PAGESIZE);

    // Test de lambda_pathconf
    lambda_pathconf("/path/to/file", _SC_NPROCESSORS_ONLN);

    // Test de lambda_sysconf
    long nprocessors = lambda_sysconf(_SC_NPROCESSORS_ONLN);
    long pagesize = lambda_sysconf(_SC_PAGESIZE);
    printf("Number of processors: %ld\n", nprocessors);
    printf("Page size: %ld\n", pagesize);

    // Test de lambda_confstr
    char buf[100] = {0};
    strcpy(buf, "test");
    lambda_confstr(_SC_PAGESIZE, buf, sizeof(buf));

    // Test de lambda_getpagesize
    int l_uname = lambda_uname(NULL);
    printf("l_uname: %d\n", l_uname);

    // Test de lambda_sethostname
    const char* new_hostname = "newhost";
    int result = lambda_sethostname(new_hostname, strlen(new_hostname));
    if (result == 0) {
        printf("Hostname set successfully to: %s\n", utsname.nodename);
    } else {
        printf("Error setting hostname: %d\n", result);
    }

    return 0;
}