#if __has_include("sqlite3.h")
#include <sqlite3.h>
#elif __has_include("lambda.h")
#include <stddef.h>
#include <lambda.h>
#endif

#include <time.h>
#include <pthread.h>
#include <string.h>

#include <stdio.h>
extern int main_lambda(int argc, char *argv[]);

int main(int argc, char *argv[]) {
  int ret = main_lambda(argc, argv);
}
