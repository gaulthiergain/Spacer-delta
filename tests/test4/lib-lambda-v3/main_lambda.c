#include <stdio.h>
#include <stdlib.h>
#include <lambda.h>
#include <time.h>

int main_lambda(int argc, char *argv[]) {
    int r1 = f1();
    printf("f1() = %d\n", r1);

    hexDumpLib("0x100000", 0x100000, 0x20);
    int r3 = f3();
    printf("f3() = %d\n", r3);
    return 1;
}