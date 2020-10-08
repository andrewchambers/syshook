/* See LICENSE file for copyright and license details. */
#include "common.h"


#if defined(__GNUC__) || defined(__clang__)
# pragma GCC diagnostic ignored "-Wformat-nonliteral"
#endif



void
weprintf(const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  fprintf(stderr, "\n%s: ", argv0);
  vfprintf(stderr, fmt, ap);
  switch (strchr(fmt, '\0')[-1]) {
  case ':':
    fprintf(stderr, " %s\n", strerror(errno));
    break;
  case '\n':
    break;
  default:
    fprintf(stderr, "\n");
    break;
  }
  va_end(ap);
}

