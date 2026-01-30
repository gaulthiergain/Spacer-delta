#include <stdio.h>

int f1();
int f3();

int f1(){
    printf("[lambda] Call f1\n");
    return 1;
}

int f3(){
    printf("[lambda] Call f3\n");
    return 3;
}
