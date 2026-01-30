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

struct node {
   int data;
   struct node *next;
};

struct node *head = NULL;
struct node *current = NULL;

void hexDumpLib (
    const char * desc,
    const void * addr,
    const int len,
    int perLine
) {
    // Silently ignore silly per-line values.

    if (perLine < 4 || perLine > 64) perLine = 16;

    int i;
    unsigned char buff[perLine+1];
    const unsigned char * pc = (const unsigned char *)addr;

    // Output description if given.

    if (desc != NULL) printf ("%s:\n", desc);

    // Length checks.

    if (len == 0) {
        printf("  ZERO LENGTH\n");
        return;
    }
    if (len < 0) {
        printf("  NEGATIVE LENGTH: %d\n", len);
        return;
    }

    // Process every byte in the data.

    for (i = 0; i < len; i++) {
        // Multiple of perLine means new or first line (with line offset).

        if ((i % perLine) == 0) {
            // Only print previous-line ASCII buffer for lines beyond first.

            if (i != 0) printf ("  %s\n", buff);

            // Output the offset of current line.

            printf ("  %04x ", i);
        }

        // Now the hex code for the specific character.

        printf (" %02x", pc[i]);

        // And buffer a printable ASCII character for later.

        if ((pc[i] < 0x20) || (pc[i] > 0x7e)) // isprint() may be better.
            buff[i % perLine] = '.';
        else
            buff[i % perLine] = pc[i];
        buff[(i % perLine) + 1] = '\0';
    }

    // Pad out last line if not exactly perLine characters.

    while ((i % perLine) != 0) {
        printf ("   ");
        i++;
    }

    // And print the final ASCII buffer.

    printf ("  %s\n", buff);
}

int f3() {
    printf("f3 1\n");
    struct node *ptr = head;
    if (ptr == NULL) {
        printf("f3: head is null\n");
        return 0;
    }
    printf("f3 2\n");

    printf("\n[head] =>\n");
    //start from the beginning
    while(ptr != NULL) {
        if (ptr->next == NULL) {
            printf(" [ %d ] => [null]\n", ptr->data);
            break;
        } 
        ptr = ptr->next;
    }

    printf("f3 3\n");

    printf(" [null]\n");
    return 32;
}

void f4(int data) {
   //create a link
   /*struct node *link = (struct node*) malloc(sizeof(struct node));
   if (link == NULL) {
      fprintf(stderr, "error");
      return;
   }*/
   struct node link;

   //link->key = key;
   link.data = data;

   //point it to old first node
   link.next = head;

   //point first to new first node
   head = &link;
}

int f5(){
    printf("f5\n");
    return 5;
}