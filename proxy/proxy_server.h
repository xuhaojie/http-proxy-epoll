#ifndef HTTPS_PROXY_PROXY_SERVER_H
#define HTTPS_PROXY_PROXY_SERVER_H

#include "connection.h"

typedef struct ProxyServer {
  int listening_socket;
  bool stats_enabled;
  char** blocklist;
  int blocklist_len;
}ProxyServer;

void accept_incoming_connections(Poll* p, ProxyServer* server);

void start_connecting_to_target(Poll* p, Connection* conn);

void start_tunneling(Poll* p, Connection* conn);

#endif  // HTTPS_PROXY_PROXY_SERVER_H
