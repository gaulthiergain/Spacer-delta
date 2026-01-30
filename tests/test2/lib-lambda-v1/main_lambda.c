#include <stdio.h>
#include <stdlib.h>
#include <lambda.h>
#include <time.h>

int main_lambda(int argc, char *argv[]) {
    printf("f1() = %d - f1() = %d\n", f1(), f1());
      return 1;
}