#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>

#define ENOTBLK   15  /* Block device required */
#define ESOCKTNOSUPPORT 44  /* Socket type not supported */
#define ESHUTDOWN 58  /* Cannot send after transport endpoint shutdown */
#define EPROCLIM        670      /* SUNOS: Too many processes */
#define EUSERS    68  /* Too many users */
#define EBADRPC   991
#define ERPCMISMATCH 1001
#define EPROGUNAVAIL 1011
#define EPROGMISMATCH 1021
#define EPROCUNAVAIL 1031
#define EAUTH 1041
#define ENEEDAUTH 1051
#define ENOATTR 1061
#define EDOOFUS 1071
#define ENOTCAPABLE 1081
#define ECAPMODE 1091

int getMax(int array[], int size)
{
  int max = array[0];
  for (int i = 1; i < size; i++)
    if (array[i] > max)
      max = array[i];
  return max;
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

int swapped = 0; // global variable to check if swap() function is called

int bubblesort(int *a, int size) // to demonstrate passing by refference in C (pointer variable receives only the base address of array)
{
    for (int i = 0; i < size; i++)
    {
        for (int j = 0; j < size - i - 1; j++)
        {
            if (a[j] > a[j + 1])
            {
            swap(a+j, a+j+1); // making a function is good instead of many lines of code in main function 
            }
        }
        if (swapped == 0)
            return 1; // use return values better than break statement
    }
    return 0; // sorted 

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

inline void swap(int *a, int *b)
{
    int temp = *b;
    *b = *a;
    *a = temp;
    swapped++;
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
 
int pancakeSort(int *list, unsigned int length)
{
    if (length < 2)
        return 0;
    int i, a, max_num_pos, moves;
 
    moves = 0;
    for (i = length;i > 1;i--)
    {
        max_num_pos = 0;
        for (a = 0;a < i;a++)
        {
            if (list[a] > list[max_num_pos])
                max_num_pos = a;
        }
        if (max_num_pos ==  i - 1)
            continue;
        if (max_num_pos)
        {
            moves++;
            doFlip(list, length, max_num_pos + 1);
        }
        doFlip(list, length, i);
    }
    return moves;
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
 
void radixsort(int arr[], int n) {
    int m = getMax(arr, n);
 
    int exp;
    for (exp = 1; m / exp > 0; exp *= 10)
        countSort(arr, n, exp);
}
 
void print(int arr[], int n) {
    int i;
    for (i = 0; i < n; i++)
        printf("%d ", arr[i]);
}
 
void shellsort(int arr[], int num)
{
    int i, j, k, tmp;
    for (i = num / 2; i > 0; i = i / 2)
    {
        for (j = i; j < num; j++)
        {
            for(k = j - i; k >= 0; k = k - i)
            {
                if (arr[k+i] >= arr[k])
                    break;
                else
                {
                    tmp = arr[k];
                    arr[k] = arr[k+i];
                    arr[k+i] = tmp;
                }
            }
        }
    }
}

void *lambda_memcpy(void *dst, const void *src, size_t len)
{
    size_t p;

    for (p = 0; p < len; ++p)
        *((unsigned char *)(((uintptr_t)dst) + p)) = *((unsigned char *)(((uintptr_t)src) + p));

    return dst;
}

void *lambda_memset(void *ptr, int val, size_t len)
{
    unsigned char *p = (unsigned char *) ptr;

    for (; len > 0; --len)
        *(p++) = (unsigned char)val;

    return ptr;
}

void *lambda_memchr(const void *ptr, int val, size_t len)
{
    uintptr_t o = 0;

    for (o = 0; o < (uintptr_t)len; ++o)
        if (*((const uint8_t *)(((uintptr_t)ptr) + o)) == (uint8_t)val)
            return (void *)((uintptr_t)ptr + o);

    return NULL; /* did not find val */
}

void *lambda_memrchr(const void *m, int c, size_t n)
{
    const unsigned char *s = m;

    c = (unsigned char) c;
    while (n--)
        if (s[n] == c)
            return (void *) (s + n);
    return 0;
}

void *lambda_memmove(void *dst, const void *src, size_t len)
{
    uint8_t *d = dst;
    const uint8_t *s = src;

    if (src > dst) {
        for (; len > 0; --len)
            *(d++) = *(s++);
    } else {
        s += len - 1;
        d += len - 1;

        for (; len > 0; --len)
            *(d--) = *(s--);
    }

    return dst;
}

int lambda_memcmp(const void *ptr1, const void *ptr2, size_t len)
{
    const unsigned char *c1 = (const unsigned char *)ptr1;
    const unsigned char *c2 = (const unsigned char *)ptr2;

    for (; len > 0; --len, ++c1, ++c2) {
        if ((*c1) != (*c2))
            return ((*c1) - (*c2));
    }

    return 0;
}

size_t lambda_strlen(const char *str)
{
    return strnlen(str, SIZE_MAX);
}

size_t lambda_strnlen(const char *str, size_t len)
{
    const char *p = memchr(str, 0, len);
    return p ? (size_t) (p - str) : len;
}

char *lambda_strncpy(char *dst, const char *src, size_t len)
{
    size_t clen;

    clen = strnlen(src, len);
    memcpy(dst, src, clen);

    /* instead of filling up the rest of left space with zeros,
     * append a termination character if we did not copy one
     */
    if (clen < len && dst[clen - 1] != '\0')
        dst[clen] = '\0';
    return dst;
}

char *lambda_strcpy(char *dst, const char *src)
{
    return strncpy(dst, src, SIZE_MAX);
}

int lambda_strncmp(const char *str1, const char *str2, size_t len)
{
    const char *c1 = (const char *)str1;
    const char *c2 = (const char *)str2;

    for (; len > 0; --len, ++c1, ++c2) {
        if ((*c1) != (*c2))
            return (int)((*c1) - (*c2));
        if ((*c1) == '\0')
            break;
    }
    return 0;
}

int lambda_strcmp(const char *str1, const char *str2)
{
    register signed char __res;

    while ((__res = *str1 - *str2++) == 0 && *str1++)
        ;

    return __res;
}

/* The following code is taken from musl libc */
#define ALIGN (sizeof(size_t))
#define ONES ((size_t) -1 / UCHAR_MAX)
#define HIGHS (ONES * (UCHAR_MAX / 2 + 1))
#define HASZERO(x) (((x) - ONES) & ~(x) & HIGHS)
#define BITOP(a, b, op) \
        ((a)[(size_t)(b) / (8*sizeof *(a))] op \
        (size_t)1 << ((size_t)(b) % (8 * sizeof *(a))))

char *lambda_strchrnul(const char *s, int c)
{
    size_t *w, k;

    c = (unsigned char)c;
    if (!c)
        return (char *)s + strlen(s);

    for (; (uintptr_t)s % ALIGN; s++)
        if (!*s || *(unsigned char *)s == c)
            return (char *)s;
    k = ONES * c;
    for (w = (void *)s; !HASZERO(*w) && !HASZERO(*w ^ k); w++)
        ;
    for (s = (void *)w; *s && *(unsigned char *)s != c; s++)
        ;
    return (char *)s;
}

char *lambda_strchr(const char *str, int c)
{
    char *r = lambda_strchrnul(str, c);
    return *(unsigned char *)r == (unsigned char)c ? r : 0;
}

char *lambda_strrchr(const char *s, int c)
{
    return lambda_memrchr(s, c, strlen(s) + 1);
}

size_t lambda_strcspn(const char *s, const char *c)
{
    const char *a = s;
    size_t byteset[32 / sizeof(size_t)];

    if (!c[0] || !c[1])
        return lambda_strchrnul(s, *c)-a;

    memset(byteset, 0, sizeof(byteset));
    for (; *c && BITOP(byteset, *(unsigned char *)c, |=); c++)
        ;
    for (; *s && !BITOP(byteset, *(unsigned char *)s, &); s++)
        ;
    return s-a;
}

size_t lambda_strspn(const char *s, const char *c)
{
    const char *a = s;
    size_t byteset[32 / sizeof(size_t)] = { 0 };

    if (!c[0])
        return 0;
    if (!c[1]) {
        for (; *s == *c; s++)
            ;
        return s-a;
    }

    for (; *c && BITOP(byteset, *(unsigned char *)c, |=); c++)
        ;
    for (; *s && BITOP(byteset, *(unsigned char *)s, &); s++)
        ;
    return s-a;
}

char *lambda_strtok(char *restrict s, const char *restrict sep)
{
    static char *p;

    if (!s && !(s = p))
        return NULL;
    s += strspn(s, sep);
    if (!*s)
        return p = 0;
    p = s + strcspn(s, sep);
    if (*p)
        *p++ = 0;
    else
        p = 0;
    return s;
}

char *lambda_strtok_r(char *restrict s, const char *restrict sep, char **restrict p)
{
    if (!s && !(s = *p))
        return NULL;
    s += strspn(s, sep);
    if (!*s)
        return *p = 0;
    *p = s + strcspn(s, sep);
    if (**p)
        *(*p)++ = 0;
    else
        *p = 0;
    return s;
}

char *lambda_strndup(const char *str, size_t len)
{
    char *__res;
    int __len;

    __len = strnlen(str, len);

    __res = malloc(__len + 1);
    if (__res) {
        memcpy(__res, str, __len);
        __res[__len] = '\0';
    }

    return __res;
}

char *lambda_strdup(const char *str)
{
    return strndup(str, SIZE_MAX);
}

/* strlcpy has different ALIGN */
#undef ALIGN
#define ALIGN (sizeof(size_t)-1)
size_t lambda_strlcpy(char *d, const char *s, size_t n)
{
    char *d0 = d;
    size_t *wd;
    const size_t *ws;

    if (!n--)
        goto finish;

    if (((uintptr_t)s & ALIGN) == ((uintptr_t)d & ALIGN)) {
        for (; ((uintptr_t) s & ALIGN) && n && (*d = *s);
             n--, s++, d++)
            ;

        if (n && *s) {
            wd = (void *)d; ws = (const void *)s;
            for (; n >= sizeof(size_t) && !HASZERO(*ws);
                 n -= sizeof(size_t), ws++, wd++)
                *wd = *ws;

            d = (void *)wd; s = (const void *)ws;
        }
    }

    for (; n && (*d = *s); n--, s++, d++)
        ;
    *d = 0;
finish:
    return d-d0 + strlen(s);
}

size_t lambda_strlcat(char *d, const char *s, size_t n)
{
    size_t l = strnlen(d, n);
    if (l == n)
        return l + strlen(s);
    return l + strlcpy(d+l, s, n-l);
}

/* GNU-specific version of strerror_r */
char *lambda_strerror_r(int errnum, char *buf, size_t buflen)
{
    const char *strerr;

    switch (errnum) {
    case EPERM:
        strerr = "Operation not permitted";
        break;
    case ENOENT:
        strerr = "No such file or directory";
        break;
    case ESRCH:
        strerr = "No such process";
        break;
    case EINTR:
        strerr = "Interrupted system call";
        break;
    case EIO:
        strerr = "Input/output error";
        break;
    case ENXIO:
        strerr = "Device not configured";
        break;
    case E2BIG:
        strerr = "Argument list too long";
        break;
    case ENOEXEC:
        strerr = "Exec format error";
        break;
    case EBADF:
        strerr = "Bad file descriptor";
        break;
    case ECHILD:
        strerr = "No child processes";
        break;
    case EDEADLK:
        strerr = "Resource deadlock avoided";
        break;
    case ENOMEM:
        strerr = "Cannot allocate memory";
        break;
    case EACCES:
        strerr = "Permission denied";
        break;
    case EFAULT:
        strerr = "Bad address";
        break;
    case ENOTBLK:
        strerr = "Block device required";
        break;
    case EBUSY:
        strerr = "Device busy";
        break;
    case EEXIST:
        strerr = "File exists";
        break;
    case EXDEV:
        strerr = "Cross-device link";
        break;
    case ENODEV:
        strerr = "Operation not supported by device";
        break;
    case ENOTDIR:
        strerr = "Not a directory";
        break;
    case EISDIR:
        strerr = "Is a directory";
        break;
    case EINVAL:
        strerr = "Invalid argument";
        break;
    case ENFILE:
        strerr = "Too many open files in system";
        break;
    case EMFILE:
        strerr = "Too many open files";
        break;
    case ENOTTY:
        strerr = "Inappropriate ioctl for device";
        break;
    case ETXTBSY:
        strerr = "Text file busy";
        break;
    case EFBIG:
        strerr = "File too large";
        break;
    case ENOSPC:
        strerr = "No space left on device";
        break;
    case ESPIPE:
        strerr = "Illegal seek";
        break;
    case EROFS:
        strerr = "Read-only file system";
        break;
    case EMLINK:
        strerr = "Too many links";
        break;
    case EPIPE:
        strerr = "Broken pipe";
        break;
    case EDOM:
        strerr = "Numerical argument out of domain";
        break;
    case ERANGE:
        strerr = "Result too large";
        break;
    case EAGAIN:
        strerr = "Resource temporarily unavailable";
        break;
    case EINPROGRESS:
        strerr = "Operation now in progress";
        break;
    case EALREADY:
        strerr = "Operation already in progress";
        break;
    case ENOTSOCK:
        strerr = "Socket operation on non-socket";
        break;
    case EDESTADDRREQ:
        strerr = "Destination address required";
        break;
    case EMSGSIZE:
        strerr = "Message too long";
        break;
    case EPROTOTYPE:
        strerr = "Protocol wrong type for socket";
        break;
    case ENOPROTOOPT:
        strerr = "Protocol not available";
        break;
    case EPROTONOSUPPORT:
        strerr = "Protocol not supported";
        break;
    case ESOCKTNOSUPPORT:
        strerr = "Socket type not supported";
        break;
    case EOPNOTSUPP:
        strerr = "Operation not supported on socket";
        break;
    case EPFNOSUPPORT:
        strerr = "Protocol family not supported";
        break;
    case EAFNOSUPPORT:
        strerr = "Address family not supported by protocol family";
        break;
    case EADDRINUSE:
        strerr = "Address already in use";
        break;
    case EADDRNOTAVAIL:
        strerr = "Can't assign requested address";
        break;
    case ENETDOWN:
        strerr = "Network is down";
        break;
    case ENETUNREACH:
        strerr = "Network is unreachable";
        break;
    case ENETRESET:
        strerr = "Network dropped connection on reset";
        break;
    case ECONNABORTED:
        strerr = "Software caused connection abort";
        break;
    case ECONNRESET:
        strerr = "Connection reset by peer";
        break;
    case ENOBUFS:
        strerr = "No buffer space available";
        break;
    case EISCONN:
        strerr = "Socket is already connected";
        break;
    case ENOTCONN:
        strerr = "Socket is not connected";
        break;
    case ESHUTDOWN:
        strerr = "Can't send after socket shutdown";
        break;
    case ETIMEDOUT:
        strerr = "Operation timed out";
        break;
    case ECONNREFUSED:
        strerr = "Connection refused";
        break;
    case ELOOP:
        strerr = "Too many levels of symbolic links";
        break;
    case ENAMETOOLONG:
        strerr = "File name too long";
        break;
    case EHOSTDOWN:
        strerr = "Host is down";
        break;
    case EHOSTUNREACH:
        strerr = "No route to host";
        break;
    case ENOTEMPTY:
        strerr = "Directory not empty";
        break;
    case EPROCLIM:
        strerr = "Too many processes";
        break;
    case EUSERS:
        strerr = "Too many users";
        break;
    case EDQUOT:
        strerr = "Disc quota exceeded";
        break;
    case ESTALE:
        strerr = "Stale NFS file handle";
        break;
    case EBADRPC:
        strerr = "RPC struct is bad";
        break;
    case ERPCMISMATCH:
        strerr = "RPC version wrong";
        break;
    case EPROGUNAVAIL:
        strerr = "RPC prog";
        break;
    case EPROGMISMATCH:
        strerr = "Program version wrong";
        break;
    case EPROCUNAVAIL:
        strerr = "Bad procedure for program";
        break;
    case ENOLCK:
        strerr = "No locks available";
        break;
    case ENOSYS:
        strerr = "Function not implemented";
        break;
    case EFTYPE:
        strerr = "Inappropriate file type or format";
        break;
    case EAUTH:
        strerr = "Authentication error";
        break;
    case ENEEDAUTH:
        strerr = "Need authenticator";
        break;
    case EIDRM:
        strerr = "Identifier removed";
        break;
    case ENOMSG:
        strerr = "No message of desired type";
        break;
    case EOVERFLOW:
        strerr = "Value too large to be stored in data type";
        break;
    case ECANCELED:
        strerr = "Operation canceled";
        break;
    case EILSEQ:
        strerr = "Illegal byte sequence";
        break;
    case ENOATTR:
        strerr = "Attribute not found";
        break;
    case EDOOFUS:
        strerr = "Programming error";
        break;
    case EBADMSG:
        strerr = "Bad message";
        break;
    case EMULTIHOP:
        strerr = "Multihop attempted";
        break;
    case ENOLINK:
        strerr = "Link has been severed";
        break;
    case EPROTO:
        strerr = "Protocol error";
        break;
    case ENOTCAPABLE:
        strerr = "Capabilities insufficient";
        break;
    case ECAPMODE:
        strerr = "Not permitted in capability mode";
        break;
    case ENOTRECOVERABLE:
        strerr = "State not recoverable";
        break;
    case EOWNERDEAD:
        strerr = "Previous owner died";
        break;
    case ENOTSUP:
        strerr = "Not supported";
        break;
    default:
        strerr = NULL;
        errno = EINVAL; /* Unknown errnum requires errno to be set */
        break;
    }

    if (!buflen)
        return buf;

    /*
     * NOTE: If target buffer is too small, we are supposed to set
     *       errno to ERANGE. We ignore this case for simplification.
     */
    if (strerr)
        strncpy(buf, strerr, buflen);
    else
        snprintf(buf, buflen, "Unknown error %d", errnum);

    /* ensure null termination */
    buf[buflen - 1] = '\0';
    return buf;
}

/* NOTE: strerror() is not thread-safe, nor reentrant-safe */
char *lambda_strerror(int errnum)
{
    /* NOTE: Our longest message is currently 48 characters. With
     *       64 characters we should have room for minor changes
     *       in the future.
     */
    static char buf[64];

    return lambda_strerror_r(errnum, buf, sizeof(buf));
}

char *lambda_strncat(char *dest, const char *src, size_t n)
{
    char *a = dest;

    dest = dest + strlen(dest);

    if (src != NULL) {
        while (n && *src) {
            n--;
            *dest++ = *src++;
        }
    }

    *dest++ = 0;
    return a;
}


void f2(int arr[], int n) {
    int i;
    int j = 100;
    printf("f2: ");
    for (i = 0; i < n; i++)
        printf("%d ", arr[i]);
    printf("\n");
    return 2;
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