#pragma once

struct addrinfo;

void async_addr_info_init(size_t threads);
void async_addr_info_cleanup(void);
int async_addr_info_resolve(const char *node, const char *service, const struct addrinfo *hints);
int async_addr_info_result(int fd, struct addrinfo **addrs);
