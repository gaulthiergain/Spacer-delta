#include <stdio.h>

int f3(){
    f1();
    printf("f3\n");
    return 3;
}

int f4(){
    printf("f4\n");
    return 4;
}

int f5(){
    printf("f5\n");
    return 5;
}

int f1(){
    printf("f1\n");
    return 1;
}