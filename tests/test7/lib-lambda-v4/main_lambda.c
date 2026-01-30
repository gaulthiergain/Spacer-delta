#include <stdio.h>
#include <stdlib.h>
#include <lambda.h>
#include <time.h>
#include <string.h>

int main_lambda(int argc, char *argv[])
{
    char * filename = malloc(sizeof(char) * 128);
  char * filename2 = malloc(sizeof(char) * 128);
    if (filename == NULL || filename2 == NULL)
  {
    return 1;
  }
  strcpy(filename, "test");
  strcpy(filename2, "test2test3");
  lambda_memcpy(filename2, filename, lambda_strlen(filename));
  printf("%s\n", filename2);
  lambda_memset(filename2, 0, lambda_strlen(filename2));
  free(filename);
  free(filename2);
      return 1;
}