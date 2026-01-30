#include <stdio.h>
#include <stdlib.h>
#include <lambda.h>
#include <time.h>

int main_lambda(int argc, char *argv[]) {
    int r1 = f1();
    int r5 = f5();
    printf("[lambda-v4] Call f1() = %d - f5() = %d\n", r1, r5);
}