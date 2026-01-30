#ifndef LIBLAMBDA
#define LIBLAMBDA

int bubblesort(int *a, int size) ;
int cycleSort(int * list, int l_len);
int getMax(int array[], int size);
int newgap(int gap)  ;
int pancakeSort(int *list, unsigned int length);
void bucketSort(int array[], int size);
void combsort(int a[], int aSize)  ;
void countingsort(int a[], int size);
void countSort(int arr[], int n, int exp) ;
void doFlip(int *list,  int length,  int num);
void merge(int a[],int i1,int j1,int i2,int j2);
void mergesort(int a[],int i,int j);
void print(int arr[], int n) ;
void quicksort(int number[25],int first,int last);
void radixsort(int arr[], int n) ;
void shellsort(int arr[], int num);
void showArray(int * array, int a_len);
void shuffle(int *a, int n);
void sort(int *a, int n);
void swap(int *a, int *b);

#endif