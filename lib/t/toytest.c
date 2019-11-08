#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "toylib.h"

int main(void)
{
  const char *p;

  p = greeting();
  if (STRNCMP(p, !=, "Hello", 5)) {
    fprintf(stderr, "greeting `%s' has bad salutation\n", p);
    exit(1);
  }
  printf("all ok\n");
  return (0);
}
