#ifndef _SE_ALLOC_H_
#define _SE_ALLOC_H_
#include <stdint.h>
#include "se_mem.h"

#define MAX_BITMAP_SIZE (1000/64 + 1)

#define MAX_DP_NUM 32
#define MAX_PORT_NUM 32
#define MAX_FLOW_NUM 1024
#define MAX_ACTION_NUM 1024
#define MAX_MISC_NUM 1024

//TODO: need get block size from data structure size
//sizeof(dp_data_structre)
#define DP_BLOCK_SIZE 512
#define PORT_BLOCK_SIZE 512
#define FLOW_BLOCK_SIZE 512
#define ACTION_BLOCK_SIZE 1024
#define MISC_BLOCK_SIZE 256

typedef enum{
  DP_POOL_C = 0,
  PORT_POOL_C, 
  FLOW_POOL_C,
  ACTION_POOL_C,
  MISC_POOL_C,
  MAX_POOL_SIZE
}pool_type_t;

typedef struct mem_pool_data{
  mem_data_t mem_data;
  struct mem_pool_data *next; //not used now
}mem_pool_t;

  
void init_all_mem_pools(void);
void *mem_pool_malloc(pool_type_t type, int32_t size);
void mem_pool_free(pool_type_t type, void *ptr);
void mem_pool_destroy(pool_type_t type);

//only for ut purpose
mem_data_t *get_mem_pool(pool_type_t type);
#endif
