#include <stdio.h>
#include <stdlib.h>

int f1(){
    int a = 200;
    char* hello = "hello\n";
    printf("f1 %d\n", a);
    a = 1;
    printf("f1 %s\n", hello);
    printf("f1 %d\n", a);
    a = a + a;
    printf("f1 %s\n", hello);
    printf("f1 %d\n", a);
    return 1;
}

int f2(){
    int r[2800 + 1];
    int i, k;
    int b, d;
    int c = 0;

    for (i = 0; i < 2800; i++) {
        r[i] = 2000;
    }
    r[i] = 0;

    for (k = 2800; k > 0; k -= 14) {
        d = 0;

        i = k;
        for (;;) {
            d += r[i] * 10000;
            b = 2 * i - 1;

            r[i] = d % b;
            d /= b;
            i--;
            if (i == 0) break;
            d *= i;
        }
        printf("%.4d", c + d / 10000);
        c = d % 10000;
    }

    return c;
}



