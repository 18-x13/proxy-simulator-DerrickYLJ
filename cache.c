#include "cache.h"

cache_t *cache_init() {
    cache_t *cache = malloc(sizeof(cache_t));
    cache->block_count = 0;
    cache->head = NULL;
    cache->tail = NULL;
    cache->bytes_available = MAX_CACHE_SIZE;
    return cache;
}

block_t *block_init() {
    block_t *block = malloc(sizeof(block_t));
    block->next = NULL;
    block->prev = NULL;
    // sio_printf("block init\n");
    return block;
}

block_t *fill_block(block_t *block, char *URL_request, char *server_response,
                    size_t response_length) {

    if (block == NULL) {
        sio_printf("block invalid\n");
        return NULL;
    }
    // sio_printf("URL source %s\n", URL_request);
    block->URL = malloc(strlen(URL_request) + 1);
    block->server_response = malloc(response_length);
    strcpy(block->URL, URL_request);
    block->URL[strlen(URL_request)] = '\0';
    memcpy(block->server_response, server_response, response_length);
    block->response_length = response_length;
    // sio_printf("URL current %s\n", block->URL);
    return block;
}

block_t *search_node(cache_t *cache, char *URL_request) {
    pthread_mutex_lock(&cache_lock);

    if (cache == NULL) {
        sio_printf("invalid cache\n");
        pthread_mutex_unlock(&cache_lock);
        return NULL;
    }
    block_t *temp = cache->head;

    if (cache->block_count != 0)
        sio_printf("first URL in cache %s\n", cache->head->URL);

    while (temp != NULL) {
        // sio_printf("begin search\n");
        // sio_printf("URL in cache : %s\n ; URL input : %s\n", temp->URL,
        // URL_request);
        if (strcmp(temp->URL, URL_request) == 0) {
            sio_printf("Found the block: %s\n", temp->URL);
            pthread_mutex_unlock(&cache_lock);
            return temp;
        }

        sio_printf("searching in cache\n");
        temp = temp->next;
    }
    pthread_mutex_unlock(&cache_lock);
    return NULL;
}

bool add_block(cache_t *cache, block_t *block) {
    pthread_mutex_lock(&cache_lock);
    if ((cache == NULL) || (block == NULL)) {
        sio_printf("invalid cache or block\n");
        pthread_mutex_unlock(&cache_lock);
        return false;
    }

    if (cache->block_count == 0) {
        cache->head = block;
        cache->tail = block;
        block->next = NULL;
        block->prev = NULL;
        cache->bytes_available -= block->response_length;
    } else {
        cache->head->prev = block;
        block->next = cache->head;
        block->prev = NULL;
        cache->head = block;
        cache->bytes_available -= block->response_length;
    }
    // sio_printf("adding new blocks in cach\n");
    cache->block_count++;
    pthread_mutex_unlock(&cache_lock);
    return true;
}

block_t *remove_block(cache_t *cache, block_t *block) {
    pthread_mutex_lock(&cache_lock);
    if ((cache == NULL) || (block == NULL)) {
        sio_printf("invalid cache or block\n");
        pthread_mutex_unlock(&cache_lock);
        return block;
    }

    if (block->prev == NULL) {
        // block is the first one
        cache->head = block->next;
        if (block->next == NULL) {
            // block is also the last one
            cache->tail = block->next;
        } else {
            // block is not the last one
            cache->head->prev = NULL;
        }
    } else {
        // block is not the first one
        block->prev->next = block->next;
        if (block->next == NULL) {
            // block is the last one
            cache->tail = block->prev;
        } else {
            // block is not the last one
            block->next->prev = block->prev;
        }
    }

    block->next = NULL;
    block->prev = NULL;
    cache->bytes_available += block->response_length;
    cache->block_count--;
    pthread_mutex_unlock(&cache_lock);
    return block;
}

void free_block(block_t *block) {
    if (block == NULL)
        return;
    free(block->server_response);
    free(block->URL);
    free(block);
}

void free_cache(cache_t *cache) {
    if (cache == NULL)
        return;
    block_t *temp = cache->head;
    while (temp != NULL) {
        block_t *next = temp->next;
        free_block(temp);
        temp = next;
    }
    free(cache);
}

void eviction(cache_t *cache) {
    block_t *remov = remove_block(cache, cache->tail);
    free_block(remov);
}

char *get_server_response(cache_t *cache, char *URL) {
    block_t *res = search_node(cache, URL);
    return res->server_response;
}