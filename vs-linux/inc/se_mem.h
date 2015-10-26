#ifndef _SE_MEM_H_
#define _SE_MEM_H_

#ifndef LUTTEST

#include "il-cvmx-wrapper.h"
//#undef likely
//#undef unlikely
#include "fpn.h"
#include "fp-includes.h"

#endif

#define MEM_BLOCK_SIZE    64
#define MAX_BLOCK_NUM    2048
#define MAX_MEM_SIZE_BYTES    MEM_BLOCK_SIZE*MAX_BLOCK_NUM
#define MAX_SHM_NAME    20



#ifdef LUTTEST  
#define cvmx_spinlock_t int
#endif 

typedef struct {
  unsigned size;
  unsigned longest[2*MAX_BLOCK_NUM-1]; 
}se_mem_t;

typedef struct mem_data {
  char *base_mem_ptr; //mem start address
  char *end; //mem end address
  se_mem_t se_mem;
  cvmx_spinlock_t se_mem_lock;
  char *shm_name;
  int block_num;
  int block_size;
  //TODO: free block data is not correctly updated, not use it now
  int free;
}mem_data_t;

mem_data_t* se_mem_init(mem_data_t *mem_data);
void *se_malloc(int size, mem_data_t *mem_data);
void se_free(void *ptr, mem_data_t *mem_data);
void se_mem_destroy(mem_data_t *mem_data);

//#define malloc se_malloc
//#define free   se_free
#endif
