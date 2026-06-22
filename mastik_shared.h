/*
 * mastik_shared.h
 * Drop-in replacement for map_offset() using MAP_SHARED.
 *
 * Mastik's built-in map_offset() uses MAP_PRIVATE, which creates a
 * copy-on-write mapping. Flush+Reload requires MAP_SHARED so spy and
 * victim share the same physical cache lines.
 *
 * Usage: include this header, call shared_map_offset() instead of map_offset().
 */
#pragma once
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>

static inline void *shared_map_offset(const char *path, uint64_t offset) {
  int fd = open(path, O_RDONLY);
  if (fd < 0) return NULL;
  size_t pgsz = sysconf(_SC_PAGE_SIZE);
  uint64_t page_off = offset & ~((uint64_t)pgsz - 1);
  char *base = mmap(NULL, pgsz, PROT_READ, MAP_SHARED, fd, (off_t)page_off);
  close(fd);
  if (base == MAP_FAILED) return NULL;
  return base + (offset & (pgsz - 1));
}
