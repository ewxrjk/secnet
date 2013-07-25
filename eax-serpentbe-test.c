#include "eax-test.h"
#include "serpent.h"
/* multiple-inclusion protection means that serpent.h's inclusion
 * by eax-serpent-test.c is suppressed, so we don't get useless
 * duplicate declarations of serpentbe_makekey and serpentbe_encrypt
 */
#define serpent_makekey serpentbe_makekey
#define serpent_encrypt serpentbe_encrypt
#include "eax-serpent-test.c"
