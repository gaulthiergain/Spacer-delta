#include <stdio.h>
#include <stdlib.h>
#include <lambda.h>
#include <time.h>

int main_lambda(int argc, char *argv[])
{
  int arr[] = { 0, 1, 2, 2, 2, 2, 1, 9, 3, 5, 5, 8, 4, 7, 0, 6, };
  int arr_k = sizeof(arr) / sizeof(arr[0]);
  int writes, i;
  printf("Original Array:\n");
  showArray(arr, arr_k);
  writes = cycleSort(arr, arr_k);
  printf("\nSorted Array:\n");
  showArray(arr, arr_k);
  printf("writes: %d\n", writes);
      return 1;
}