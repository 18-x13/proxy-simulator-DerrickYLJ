#include "csapp.h"
#include "http_parser.h"
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
/*
 * Debug macros, which can be enabled by adding -DDEBUG in the Makefile
 * Use these if you find them useful, or delete them if not
 */
#ifdef DEBUG
#define dbg_assert(...) assert(__VA_ARGS__)
#define dbg_printf(...) fprintf(stderr, __VA_ARGS__)
#else
#define dbg_assert(...)
#define dbg_printf(...)
#endif

/*
 * Max cache and object sizes
 * You might want to move these to the file containing your cache implementation
 */
#define MAX_CACHE_SIZE (1024 * 1024)
#define MAX_OBJECT_SIZE (100 * 1024)

pthread_mutex_t cache_lock;

typedef struct block {
    char *URL;
    char *server_response; // unsure about the type
    struct block *next;
    struct block *prev;
    size_t response_length;
} block_t;

typedef struct cache {
    struct block *head;
    struct block *tail;
    unsigned int block_count;
    size_t bytes_available;
} cache_t;

cache_t *cache_init(); // initialize the cache
block_t *block_init(); // initialize the block
block_t *fill_block(block_t *block, char *URL, char *server_response,
                    size_t res_length); // fill in the block with URL and
                                        // correponding server_response
block_t *search_node(cache_t *cache,
                     char *URL_request);        // search the block based on URL
bool add_block(cache_t *cache, block_t *block); // add block to the cache
block_t *remove_block(cache_t *cache,
                      block_t *blcok); // remove the corresponding block
void free_block(block_t *block);       // free the block
void free_cache(cache_t *cache); // free the whole cache including the block
void eviction(cache_t *cache);   // evict the whole cache
char *get_server_response(cache_t *cache,
                          char *URL); // get the response based on the URL
// 1. unsure about how the server repsonse can be related to URL
// 2. how does concurrency come into place
// 3. the cache memory and total size
