/*
 * Loader Implementation
 *
 * 2018, Operating Systems
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "exec_parser.h"
#include <signal.h>
#include <sys/mman.h>
#include <unistd.h>

static so_exec_t *exec;
static struct sigaction default_handler; 
static int page_size = 0;
static int fd;

static void handler(int signum, siginfo_t *info, void *context) {
  if (signum != SIGSEGV)
    return;

  uintptr_t cur_addr = (uintptr_t)info->si_addr;
  int page_no;       
  int flags = MAP_PRIVATE | MAP_FIXED;
  int outside_mapped = 0;



  struct so_seg *found = NULL;
  struct so_seg *temp = NULL;
  for (int i = 0; i < exec->segments_no; ++i) {
    temp = &exec->segments[i];
    if (cur_addr >= temp->vaddr && cur_addr < temp->vaddr + temp->mem_size) {
      // segment found
      found = temp;
      break;
    }
  }

  char *mapped = (char *)found->data;
  page_no = (cur_addr - found->vaddr) / page_size;

  if (!found || mapped[page_no] == 1) {
    default_handler.sa_sigaction(signum, info, context);
    return;
  }

  if (found->file_size < found->mem_size) {
    if (found->file_size < page_no * page_size) {
      /* Undefined behaviour */
      flags |= MAP_ANONYMOUS;
    } else if ((page_no + 1) * page_size > found->file_size) {
      /* It exceeds file boundaries by mapdif bytes */
      outside_mapped = (page_no + 1) * page_size - found->file_size;
    }
  }
  /* Map page: */
  char *p = mmap((void *)found->vaddr + page_no * page_size, page_size, found->perm,
           flags, fd, found->offset + page_no * page_size);

  if (p == MAP_FAILED)
    exit(-ENOMEM);

  if (outside_mapped != 0) {
    /* We mapped outside of file boundaries. Zero those bytes */
    uintptr_t temp =found->vaddr + page_no * page_size + (page_size - outside_mapped);
    memset((char *)temp, 0, outside_mapped);
  }

  /* Mark page as mapped: */
  mapped[page_no] = 1;
}


int so_init_loader(void) {

  if (!page_size) {
    page_size = getpagesize();
  }
  /* TODO: initialize on-demand loader */

  struct sigaction action;
  int ret;

  action.sa_sigaction = handler;
  sigemptyset(&action.sa_mask);
  sigaddset(&action.sa_mask, SIGSEGV);
  action.sa_flags = SA_SIGINFO;

  ret = sigaction(SIGSEGV, &action, &default_handler);
  if (ret == -1)
    exit(-1);

  return -1;
}

int so_execute(char *path, char *argv[]) {

  fd = open(path, O_RDONLY);

  if (fd == -1) {
    exit(-ENOENT);
  }

  exec = so_parse_exec(path);
  if (!exec)
    return -1;

  int no_pages = 0;
  struct so_seg *cur_segm = NULL;
  for (int i = 0; i < exec->segments_no; ++i) {
    cur_segm = &exec->segments[i];
    no_pages = cur_segm->mem_size / page_size;
    if (cur_segm->mem_size % page_size != 0) {
      no_pages++;
    }
    char *ret = calloc(no_pages, 1);
    if (!ret) {
      return -1;
    }
    cur_segm->data = ret;
  }

  so_start_exec(exec,argv);
  // free used memory
  // unmap every mapped page from every segment
  cur_segm = NULL;
  char *mapped = NULL;
  no_pages = 0;
  int ret;
  for (int i = 0; i < exec->segments_no; ++i) {
    cur_segm = &exec->segments[i];
    mapped = (char *)cur_segm->data;

    no_pages = cur_segm->mem_size / page_size;
    if (cur_segm->mem_size % page_size != 0) {
      no_pages++;
    }

    for (int j = 0; j < no_pages; ++j) {
      if (mapped[j] == 1) {
        uintptr_t addr = cur_segm->vaddr + j * page_size;
        ret = munmap((char *)addr, page_size);
        if (ret == -1)
          exit(-ENOMEM);
      }
    }

    free(cur_segm->data);
  }

  return -1;
}
