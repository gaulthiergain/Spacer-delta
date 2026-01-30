#include <stdio.h>
#include <stdlib.h>
#include <lambda.h>
#include <time.h>

int main_lambda(int argc, char *argv[]) {
    int r1 = f1();
    int r3 = f3();
    printf("[lambda-v3] Call f1() = %d - f3() = %d\n", r1, r3);
}