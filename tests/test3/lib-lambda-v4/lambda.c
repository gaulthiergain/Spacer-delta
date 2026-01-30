#include <stdio.h>



int f1(){
    int a = 0;
    const hello = "hello\n";
    printf("f1 %d\n", a);
    printf("f1 %s\n", hello);
    return 1;
}



int f3(){
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