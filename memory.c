/* See LICENSE file for copyright and license details. */
#include "common.h"


char *
get_string(pid_t pid, unsigned long int addr, size_t *lenp, const char **errorp)
{
#if defined(__x86_64__) && defined(__IPL32__)
# error "x32 is not supported, would not be able to read memory from 64-bit applications with current method"
#endif
  struct iovec inv, outv;
  size_t off = 0, size = 0, page_off, read_size;
  char *out = NULL, *in = (char *)addr, *p;
  page_off = (size_t)addr % sizeof(PAGE_SIZE);
  read_size = PAGE_SIZE - page_off;
  *errorp = NULL;
  for (;; read_size = PAGE_SIZE) {
    out = realloc(out, size + PAGE_SIZE);
    if (!out)
      eprintf("realloc:");
    inv.iov_base  = &in[off];
    inv.iov_len   = read_size;
    outv.iov_base = &out[off];
    outv.iov_len  = read_size;
    if (process_vm_readv(pid, &outv, 1, &inv, 1, 0) != (ssize_t)read_size) {
      *errorp = errno == EFAULT ? "<invalid address>" : "<an error occured during reading of string>";
      *lenp = 0;
      free(out);
      return 0;
    }
    p = memchr(&out[off], 0, read_size);
    if (p) {
      *lenp = (size_t)(p - out);
      return out;
    }
    off += read_size;
  }
}


int
get_struct(pid_t pid, unsigned long int addr, void *out, size_t size, const char **errorp)
{
  struct iovec inv, outv;
  if (!addr) {
    *errorp = "NULL";
    return -1;
  }
  *errorp = NULL;
#if defined(__x86_64__) && defined(__IPL32__)
# error "x32 is not supported, would not be able to read memory from 64-bit applications with current method"
#endif
  inv.iov_base  = (void *)addr;
  inv.iov_len   = size;
  outv.iov_base = out;
  outv.iov_len  = size;
  if (process_vm_readv(pid, &outv, 1, &inv, 1, 0) == (ssize_t)size)
    return 0;
  *errorp = errno == EFAULT ? "<invalid address>" : "<an error occured during reading of memory>";
  return -1;
}


char *
get_memory(pid_t pid, unsigned long int addr, size_t n, const char **errorp)
{
  char *out = malloc(n + (size_t)!n);
  if (!out)
    eprintf("malloc:");
  if (get_struct(pid, addr, out, n, errorp)) {
    free(out);
    return NULL;
  }
  return out;
}