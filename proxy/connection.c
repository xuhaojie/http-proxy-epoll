#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "../log.h"
#include "connection.h"

void tunnel_buffer_reset(TunnelBuffer* self){
	self->read_ptr = self->start;
	self->write_ptr = self->start;
}

Connection* connection_create(bool stats_enabled, char** blocklist, int blocklist_len) {
	Connection* conn = calloc(1, sizeof(Connection));
	conn->client_socket = -1;
	conn->client_socket_dup = -1;
	conn->target_socket = -1;
	conn->target_socket_dup = -1;

	// conn->target_host = calloc(MAX_HOST_LEN, sizeof(char));
	// conn->target_port = calloc(MAX_PORT_LEN, sizeof(char));
	// conn->http_version = calloc(HTTP_VERSION_LEN, sizeof(char));
	// conn->client_hostport = calloc(HOST_PORT_BUF_SIZE, sizeof(char));
	// conn->target_hostport = calloc(HOST_PORT_BUF_SIZE, sizeof(char));

//	char* buffer = malloc(BUFFER_SIZE * sizeof(char));
//	conn->to_target_buffer.start = buffer;
	conn->to_target_buffer.read_ptr = conn->to_target_buffer.start ;
	conn->to_target_buffer.write_ptr = conn->to_target_buffer.start ;

//	buffer = malloc(BUFFER_SIZE * sizeof(char));
//	conn->to_client_buffer.start = buffer;
	conn->to_client_buffer.read_ptr = conn->to_client_buffer.start;
	conn->to_client_buffer.write_ptr = conn->to_client_buffer.start;

	conn->halves_closed = 0;
	conn->n_bytes_transferred = 0;

	conn->stats_enabled = stats_enabled;
	if (stats_enabled) {
		timespec_get(&conn->started_at, TIME_UTC);
	}

	conn->blocklist = blocklist;
	conn->blocklist_len = blocklist_len;
	conn->is_blocked = false;
	conn->https = false;
	return conn;
}

void connection_print_stats(Connection* conn) {
	if (!conn->stats_enabled || conn->target_hostport[0] == '\0') {
		return;
	}

	struct timespec ended_at;
	timespec_get(&ended_at, TIME_UTC);
	unsigned int milliseconds_elapsed =	(ended_at.tv_sec - conn->started_at.tv_sec) * 1000 + (ended_at.tv_nsec - conn->started_at.tv_nsec) / 1000000;
	LOG_INFO("Hostname: %s, Size: %llu bytes, Time: %.3f sec%s\n", conn->target_host,	conn->n_bytes_transferred, milliseconds_elapsed / 1000.0, conn->is_blocked ? " [Blocked]" : "");
}

void connection_destroy(Connection* conn) {
	connection_print_stats(conn);

	if (conn->client_socket_dup >= 0) {
		close(conn->client_socket_dup);
	}

	if (conn->client_socket >= 0) {
		shutdown(conn->client_socket, SHUT_RDWR);
		close(conn->client_socket);
	}

	if (conn->target_socket_dup >= 0) {
		close(conn->target_socket_dup);
	}

	if (conn->target_socket >= 0) {
		shutdown(conn->target_socket, SHUT_RDWR);
		close(conn->target_socket);
	}

//	free(conn->client_hostport);
//	free(conn->target_hostport);
//	free(conn->target_host);
//	free(conn->target_port);
//	free(conn->http_version);
//	free(conn->to_target_buffer.start);
//	free(conn->to_client_buffer.start);

	free(conn);
}

void connection_set_client_hostport(Connection* conn, const struct sockaddr_in* client_addr) {
	inet_ntop(AF_INET, &client_addr->sin_addr, conn->client_hostport, INET_ADDRSTRLEN);
	strcat(conn->client_hostport, ":");
	char client_port[MAX_PORT_LEN];
	sprintf(client_port, "%hu", ntohs(client_addr->sin_port));
	strcat(conn->client_hostport, client_port);
}

void connection_set_target_hostport(Connection* conn) {
	strcpy(conn->target_hostport, conn->target_host);
	strcat(conn->target_hostport, ":");
	strcat(conn->target_hostport, conn->target_port);
}
