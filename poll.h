#ifndef HTTPS_PROXY_POLL_H
#define HTTPS_PROXY_POLL_H

#include <stdbool.h>

struct Poll;
typedef struct Poll Poll;
struct Poll* poll_create();

void poll_destroy(struct Poll* p);

int poll_run(struct Poll* p);

typedef void (*poll_callback)(struct Poll* p, void* data);

int poll_set_on_read_callback(struct Poll* p, int fd, void* data, bool one_shot, bool edge_triggered, poll_callback callback);

int poll_set_on_write_callback(struct Poll* p, int fd, void* data, bool one_shot, bool edge_triggered, poll_callback callback);

#endif  // HTTPS_PROXY_POLL_H
