#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <lambda.h>



void radixsort(int arr[], int n) {
    int m = getMax(arr, n);
 
    int exp;
    for (exp = 1; m / exp > 0; exp *= 10)
        countSort(arr, n, exp);
}

bool check_sorted(int *a, int n){
  while ( --n >= 1 ) {
    if ( a[n] < a[n-1] ) return false;
  }
  return true;
}

void shuffle(int *a, int n){
  int i, t, r;
  for(i=0; i < n; i++) {
    t = a[i];
    r = rand() % n;
    a[i] = a[r];
    a[r] = t;
  }
}

void sort(int *a, int n){
  while ( !check_sorted(a, n) ) shuffle(a, n);
}

int swapped = 0; // global variable to check if swap() function is called
void swap(int *a, int *b)
{
    int temp = *b;
    *b = *a;
    *a = temp;
    swapped++;
}

int getMax(int array[], int size)
{
  int max = array[0];
  for (int i = 1; i < size; i++)
    if (array[i] > max)
      max = array[i];
  return max;
}
void bucketSort(int array[], int size)
{
  // The size of bucket must be at least the (max+1) but
  // we cannot assign declare it as int bucket(max+1) in C as
  // it does not support dynamic memory allocation.
  // So, its size is provided statically.
  int bucket[10];
  const int max = getMax(array, size);
  for (int i = 0; i <= max; i++)
  {
    bucket[i] = 0;
  }
  for (int i = 0; i < size; i++)
  {
    bucket[array[i]]++;
  }
  for (int i = 0, j = 0; i <= max; i++)
  {
    while (bucket[i] > 0)
    {
      array[j++] = i;
      bucket[i]--;
    }
  }
}

int newgap(int gap)  
{  
    gap = (gap * 10) / 13;  
    if (gap == 9 || gap == 10)  
        gap = 11;  
    if (gap < 1)  
        gap = 1;  
    return gap;  
}  
   
void combsort(int a[], int aSize)  
{  
    int gap = aSize;  
    int temp, i;  
    for (;;)  
    {  
        gap = newgap(gap);  
        int swapped = 0;  
        for (i = 0; i < aSize - gap; i++)   
        {  
            int j = i + gap;  
            if (a[i] > a[j])  
            {  
                temp = a[i];  
                a[i] = a[j];  
                a[j] = temp;  
                swapped  =  1;  
            }  
        }  
        if (gap  ==  1 && !swapped)  
            break;  
    }  
}

void countingsort(int a[], int size){
    int max = 0;
    for (int i = 0; i < size; i++){
        if (max < a[i]) max = a[i];
    }
    int* count =  (int *)calloc(max, sizeof(int));  //TODO
    for (int i = 1; i < size; i++){
        count[ a[i]] ++;
    }
    printf("\nSorted list:\n"); // Display the sorted array  
    for (int i = 0; i <= max; i++){
        for (int j = 0; j < count[i]; j++)
            printf("%d ", i);
    }
}

 /*
 * Sort an array in place and return the number of writes.
 */
int cycleSort(int * list, int l_len)
{
  int cycleStart, writes = 0;
 
  /* Loop through the array to find cycles to rotate. */
  for (cycleStart = 0; cycleStart < l_len - 1; ++cycleStart)
  {
    int item = list[cycleStart];
    int swap_tmp, i;
 
    /* Find where to put the item. */
    int pos = cycleStart;
    for (i = cycleStart + 1; i < l_len; ++i)
    {
      if (list[i] < item)
      {
        ++pos;
      }
    }
 
    /* If the item is already there, this is not a cycle. */
    if (pos == cycleStart)
    {
      continue;
    }
 
    /* Otherwise, put the item there or right after any duplicates. */
    while (item == list[pos])
    {
      ++pos;
    }
    swap_tmp = list[pos];
    list[pos] = item;
    item = swap_tmp;
    ++writes;
 
    /* Rotate the rest of the cycle. */
    while (pos != cycleStart)
    {
      /* Find where to put the item. */
      pos = cycleStart;
      for (i = cycleStart + 1; i < l_len; ++i)
      {
        if (list[i] < item)
        {
          ++pos;
        }
      }
 
      /* Put the item there or right after any duplicates. */
      while (item == list[pos])
      {
        ++pos;
      }
      swap_tmp = list[pos];
      list[pos] = item;
      item = swap_tmp;
      ++writes;
    }
  }
 
  return writes;
}
 
void mergesort(int a[],int i,int j)
{
	int mid;
		
	if(i<j)
	{
		mid=(i+j)/2;
		mergesort(a,i,mid);		//left recursion
		mergesort(a,mid+1,j);	//right recursion
		merge(a,i,mid,mid+1,j);	//merging of two sorted sub-arrays
	}
}
 
void merge(int a[],int i1,int j1,int i2,int j2)
{
	int temp[50];	//array used for merging
	int i,j,k;
	i=i1;	//beginning of the first list
	j=i2;	//beginning of the second list
	k=0;
	
	while(i<=j1 && j<=j2)	//while elements in both lists
	{
		if(a[i]<a[j])
			temp[k++]=a[i++];
		else
			temp[k++]=a[j++];
	}
	
	while(i<=j1)	//copy remaining elements of the first list
		temp[k++]=a[i++];
		
	while(j<=j2)	//copy remaining elements of the second list
		temp[k++]=a[j++];
		
	//Transfer elements from temp[] back to a[]
	for(i=i1,j=0;i<=j2;i++,j++)
		a[i]=temp[j];
}
 
void doFlip(int *list,  int length,  int num)
{
    int swap;
    for (int i = 0;i < --num;i++)
    {
        swap = list[i];
        list[i] = list[num];
        list[num] = swap;
    }
}

void quicksort(int number[25],int first,int last){
   int i, j, pivot, temp;

   if(first<last){
      pivot=first;
      i=first;
      j=last;

      while(i<j){
         while(number[i]<=number[pivot]&&i<last)
            i++;
         while(number[j]>number[pivot])
            j--;
         if(i<j){
            temp=number[i];
            number[i]=number[j];
            number[j]=temp;
         }
      }

      temp=number[pivot];
      number[pivot]=number[j];
      number[j]=temp;
      quicksort(number,first,j-1);
      quicksort(number,j+1,last);

   }
}

void countSort(int arr[], int n, int exp) {
    int output[n]; // output array
    int i, count[10] = { 0 };
 
    // Store count of occurrences in count[]
    for (i = 0; i < n; i++)
        count[(arr[i] / exp) % 10]++;
 
    for (i = 1; i < 10; i++)
        count[i] += count[i - 1];
 
    // Build the output array
    for (i = n - 1; i >= 0; i--) {
        output[count[(arr[i] / exp) % 10] - 1] = arr[i];
        count[(arr[i] / exp) % 10]--;
    }
 
    for (i = 0; i < n; i++)
        arr[i] = output[i];
}

 
void print(int arr[], int n) {
    int i;
    for (i = 0; i < n; i++)
        printf("%d ", arr[i]);
}

void f3(int arr[], int n) {
    int i;
    for (i = 0; i < n; i++)
        printf("-> %d ", arr[i]);
    return 3;
}
void showArray(int * array, int a_len)
{
  int ix;
  for (ix = 0; ix < a_len; ++ix)
  {
    printf("%d ", array[ix]);
  }
  putchar('\n');
 
  return;
}