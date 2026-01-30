#include <stdio.h>
#include <stdlib.h>
#include <lambda.h>
#include <time.h>

int main_lambda(int argc, char *argv[]) {
    int r1 = f1();
    int r2 = f2();
    printf("[lambda-v1-main] Call f1() = %d - f2() = %d\n", r1, r2);
}