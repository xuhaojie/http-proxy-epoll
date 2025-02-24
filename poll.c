#include "poll.h"
#include <errno.h>
#include <malloc.h>
#include <sys/epoll.h>
#include <unistd.h>
#include <stdbool.h>
#include <assert.h>
#define EPOLL_MAX_EVENTS 64

typedef struct Poll {
	int epoll_fd;
} Poll;

Poll* poll_create() {
	int epoll_fd = epoll_create1(0);
	if (epoll_fd < 0) {
		return NULL;
	}

	Poll* p = malloc(sizeof(Poll));
	p->epoll_fd = epoll_fd;
	return p;
}

void poll_destroy(Poll* p) {
	close(p->epoll_fd);
	free(p);
}

typedef struct PollTask {
	void* data;
	bool one_shot;
	poll_callback callback;
} PollTask;

int poll_set_event_callback(Poll* p, int fd, void* data, uint32_t base_events, bool one_shot, bool edge_triggered, poll_callback callback) {
 
// FIXME:
// since we only free the task when it's completed, submitting another task before the first one is completed on the same fd results in `task` being leaked.

	PollTask* task = malloc(sizeof(PollTask));
	task->data = data;
	task->one_shot = one_shot;
	task->callback = callback;

	struct epoll_event event;
	event.data.ptr = task;
	event.events = base_events;
	if (one_shot) {
		event.events |= EPOLLONESHOT;
	}
	if (edge_triggered) {
		event.events |= EPOLLET;
	}

	// try `mod` first, then `add` if `mod` fails
	if (epoll_ctl(p->epoll_fd, EPOLL_CTL_MOD, fd, &event) < 0) {
		if (errno != ENOENT) {
			free(task);
			return -1;
		}

		if (epoll_ctl(p->epoll_fd, EPOLL_CTL_ADD, fd, &event) < 0) {
			free(task);
			return -1;
		}
	}

	return 0;
}

inline int poll_set_on_read_callback(Poll* p, int fd, void* data, bool one_shot, bool edge_triggered, poll_callback callback) {
	return poll_set_event_callback(p, fd, data, EPOLLIN, one_shot, edge_triggered, callback);
}

inline int poll_set_on_write_callback(Poll* p, int fd, void* data, bool one_shot, bool edge_triggered, poll_callback callback) {
	return poll_set_event_callback(p, fd, data, EPOLLOUT, one_shot, edge_triggered, callback);
}

int poll_run(Poll* p) {
	struct epoll_event events[EPOLL_MAX_EVENTS];
	while (true) {
		int num_events = epoll_wait(p->epoll_fd, events, EPOLL_MAX_EVENTS, -1);
		if (num_events < 0) {
			return num_events;
		}
		struct epoll_event* ev = events;
		for (int i = 0; i < num_events; i++) {
			PollTask* task = ev->data.ptr;
			++ev;
			assert(task);
			task->callback(p, task->data);
			// If it's one-shot, this task will not be used again.
			// Otherwise, subsequent notifications will return the same task pointer.
			if (task->one_shot) {
				free(task);
			}
		}
	}
}
