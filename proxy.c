/*
 * Starter code for proxy lab.
 * Feel free to modify this code in whatever way you wish.
 */

/* Some useful includes to help you get started */

#include <assert.h>
#include <ctype.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include "csapp.h"
#include "http_parser.h"
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "cache.h"
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

cache_t *cache = NULL;

void doit(int cfd);
void clienterror(int fd, char *cause, char *errnum, char *shortmsg,
                 char *longmsg);
typedef struct sockaddr SA;
void *thread(void *vargo);

/*
 * String to use for the User-Agent header.
 * Don't forget to terminate with \r\n
 */
static const char *header_user_agent = "Mozilla/5.0"
                                       " (X11; Linux x86_64; rv:3.10.0)"
                                       " Gecko/20191101 Firefox/63.0.1";

int main(int argc, char **argv) {
    int *connfd;
    pthread_t tid;

    // sio_printf("1\n");
    if (argc != 2) {
        fprintf(stderr, "usage: %s <port>\n", argv[0]);
        exit(1);
    }
    // sio_printf("2\n");
    printf("%s", header_user_agent);
    int listenfd;
    char hostname[MAXLINE] = "www.cmu.edu", port[MAXLINE] = "80";
    socklen_t clientlen;
    struct sockaddr_storage clientaddr;
    /* Check command-line args */
    // sio_printf("3\n");
    listenfd = open_listenfd(argv[1]);
    signal(SIGPIPE, SIG_IGN);
    cache = cache_init();
    while (1) {
        clientlen = sizeof(clientaddr);
        connfd = malloc(sizeof(int));
        *connfd = accept(listenfd, (SA *)&clientaddr, &clientlen);
        getnameinfo((SA *)&clientaddr, clientlen, hostname, MAXLINE, port,
                    MAXLINE, 0);
        sio_printf("Accepted connection from (%s, %s)\n", hostname, port);
        pthread_create(&tid, NULL, thread, connfd);
    }
    free_cache(cache);
    return 0;
}

void *thread(void *vargo) {
    int connfd = *((int *)vargo);
    pthread_detach(pthread_self());
    free(vargo);
    doit(connfd);
    close(connfd);
    return NULL;
}

void clienterror(int fd, char *cause, char *errnum, char *shortmsg,
                 char *longmsg) {
    char buf[MAXLINE], body[MAXBUF];
    /* Build the HTTP response body */
    sprintf(body, "<html><title>Tiny Error</title>");
    sprintf(body,
            "%s<body bgcolor="
            "ffffff"
            ">\r\n",
            body);
    sprintf(body, "%s%s: %s\r\n", body, errnum, shortmsg);
    sprintf(body, "%s<p>%s: %s\r\n", body, longmsg, cause);
    sprintf(body, "%s<hr><em>The Tiny Web server</em>\r\n", body);
    /* Print the HTTP response */
    sprintf(buf, "HTTP/1.0 %s %s\r\n", errnum, shortmsg);
    rio_writen(fd, buf, strlen(buf));
    sprintf(buf, "Content-type: text/html\r\n");
    rio_writen(fd, buf, strlen(buf));
    sprintf(buf, "Content-length: %d\r\n\r\n", (int)strlen(body));
    rio_writen(fd, buf, strlen(buf));
    rio_writen(fd, body, strlen(body));
}

void doit(int confd) {
    assert(cache != NULL);
    char buffer[MAXLINE];
    parser_t *par1 = parser_new();
    int count = 0;

    rio_t rio_client;
    rio_t rio_server;

    // read client's request
    rio_readinitb(&rio_client, confd);

    // There is no line
    if (rio_readlineb(&rio_client, (void *)buffer, MAXLINE) != 0) {
        count++;
    }

    if (count == 0) {
        printf("there is no line from client\n");
        return;
    }

    // parse the request from the client
    parser_state res = parser_parse_line(par1, buffer);
    if (res != REQUEST) {
        return;
    }
    const char *command = NULL;
    const char *hostname = NULL;
    const char *port = NULL;
    const char *path = NULL;
    const char *http = NULL;
    const char *uri = NULL;
    const char *http_version = NULL;

    parser_retrieve(par1, METHOD, &command);
    parser_retrieve(par1, HOST, &hostname);
    parser_retrieve(par1, SCHEME, &http);
    parser_retrieve(par1, URI, &uri);
    parser_retrieve(par1, PORT, &port);
    parser_retrieve(par1, PATH, &path);
    parser_retrieve(par1, HTTP_VERSION, &http_version);

    // GET command valid
    if (strcasecmp("GET", command) != 0) {
        clienterror(confd, command, "501", "Not GET", "Cannot be requested");
    }

    // begin search in the cache
    char URL[MAXBUF];

    snprintf(URL, MAXBUF, "http://%s:%s%s", hostname, port,
             path); // what should this be like?

    // sio_printf("This is %s\n", URL);
    assert(cache != NULL);
    block_t *found_block = search_node(cache, URL);
    if (found_block != NULL) {
        // find the server_response

        // move the block to the first
        found_block = remove_block(cache, found_block);
        if (add_block(cache, found_block)) {
            sio_printf("find the block in cache: %s\n", found_block->URL);
            rio_writen(confd, (void *)(found_block->server_response),
                       found_block->response_length);
        }

    } else {
        // not find the server_response

        // handle headers

        while ((rio_readlineb(&rio_client, buffer, MAXLINE) > 0) &&
               ((strcmp(buffer, "\r\n")) != 0)) {

            if (parser_parse_line(par1, buffer) == ERROR) {
                printf("error parsing \n");
                return;
            }
        }

        char formal_request[MAXBUF];
        snprintf(formal_request, MAXBUF, "GET %s HTTP/1.0\r\n", path);
        header_t *current_header = NULL;
        while ((current_header = parser_retrieve_next_header(par1)) != NULL) {
            if (strstr("User-Agent", current_header->name) != NULL) {
                current_header->name = "User-Agent";
                current_header->value =
                    "Mozilla/5.0 (X11; Linux x86 64; rv:3.10.0) Gecko/20191101 "
                    "Firefox/63.01";
            } else if (strstr("Connection", current_header->name) != NULL) {
                current_header->name = "Connection";
                current_header->value = "close";
            } else if (strstr("Proxy-Connection", current_header->name) !=
                       NULL) {
                current_header->name = "Proxy-Connection";
                current_header->value = "close";
            } else if (strstr("Host", current_header->name) != NULL) {
                snprintf(current_header->value, MAXBUF, "%s:%s", hostname,
                         port);
                current_header->name = "Host";
                // current_header->value = hostname;
            }
            char temp[MAXLINE];
            sprintf(temp, "%s: %s\r\n", current_header->name,
                    current_header->value);
            strcat(formal_request, temp);
        }

        strcat(formal_request, "\r\n");

        // establish connect with the server
        // hostname is "www.cmu.edu" is that correct?
        // sio_printf("hostname: %s, port : %s\n",hostname, port);
        int proxy_fd = open_clientfd(hostname, port);

        if (proxy_fd == -1) {
            // parser_free(par1);
            return;
        }

        // error handling required
        rio_readinitb(&rio_server, proxy_fd);
        rio_writen(proxy_fd, formal_request, strlen(formal_request));
        // sio_printf(formal_request);
        // send the response back to the client
        char *big_temp = malloc(MAX_OBJECT_SIZE + MAXLINE);
        size_t i;
        size_t res_size_count = 0;
        bool check_size = true;
        assert(cache != NULL);
        while ((i = rio_readnb(&rio_server, big_temp + res_size_count,
                               MAXLINE)) != 0) {
            rio_writen(confd, (void *)(big_temp + res_size_count), i);
            if (res_size_count + i > MAX_OBJECT_SIZE) {
                check_size = false;
                res_size_count = 0;
            } else {
                res_size_count += i;
            }
        }
        assert(cache != NULL);
        if (check_size) {
            // add the new block

            // add new block

            block_t *found_block = search_node(cache, URL);

            if (found_block == NULL) {
                pthread_mutex_lock(&cache_lock);
                while ((cache->bytes_available < res_size_count) &&
                       (cache->tail != NULL)) {
                    // clear space if not enough
                    block_t *block = cache->tail;
                    block->prev->next = block->next;
                    if (block->next == NULL) {
                        // block is the last one
                        cache->tail = block->prev;
                    } else {
                        // block is not the last one
                        block->next->prev = block->prev;
                    }
                    block->next = NULL;
                    block->prev = NULL;
                    cache->bytes_available += block->response_length;
                    cache->block_count--;
                    free_block(block);

                    // free_block(remove_block(cache, cache->tail));
                }
                block_t *new = block_init();
                new = fill_block(new, URL, (char *)big_temp, res_size_count);
                sio_printf("URL current %s\n", new->URL);
                pthread_mutex_unlock(&cache_lock);
                add_block(cache, new);
            }

            // add_block(cache, new);
            sio_printf("adding new blocks\n");
        } else {
            free(big_temp);
        }
        sio_printf("cache numbers right now: %d; URL stored : %s\n",
                   cache->block_count, cache->head->URL);

        block_t *temp = cache->head;
        while (temp != NULL) {
            sio_printf("the cache stores : %s\n", temp->URL);
            temp = temp->next;
        }
        close(proxy_fd);

        // parser_free(par1);
    }
}
// 1. check the size of response
// 2. logic: initialize the cache in main at beginning -> after parsing, search
// in the cache (1) found, get the response and give back, put the found block
// to
// the first (2) not, normal process, and add the new block (if the space not
// enough, keep evicting until it fits)
// 3. how to consider the concurrency