#include <stdio.h>

int f1(){
    printf("f1\n");
    return 1;
}


int f3(){
    f1();
    printf("f3\n");
    return 3;
}
