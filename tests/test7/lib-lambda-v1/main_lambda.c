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

  lambda_memchr(filename, 's', lambda_strlen(filename));
  lambda_memrchr(filename, 's', lambda_strlen(filename));
  lambda_memmove(filename2, filename, lambda_strlen(filename));
  lambda_memcmp(filename, filename2, lambda_strlen(filename));
  lambda_strlen(filename);
  lambda_strnlen(filename, lambda_strlen(filename));
  lambda_strncpy(filename2, filename, lambda_strlen(filename));
  lambda_strcpy(filename2, filename);
  lambda_strncmp(filename, filename2, lambda_strlen(filename));
  lambda_strcmp(filename, filename2);
  lambda_strchrnul(filename, 's');
  lambda_strchr(filename, 's');

  free(filename);
  free(filename2);
  return 1;
}