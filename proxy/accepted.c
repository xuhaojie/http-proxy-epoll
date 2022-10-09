#include <arpa/inet.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include "../log.h"
#include "../poll.h"
#include "../util.h"
#include "proxy_server.h"

#define DEFAULT_HTTP_PORT "80"
#define DEFAULT_HTTPS_PORT "443"

void handle_client_connect_request_readability(Poll* p, Connection* conn);

void accept_incoming_connections(Poll* p, ProxyServer* server) {
	// accept all pending connections
	while (true) {
		struct sockaddr_in client_addr;
		socklen_t addrlen = sizeof(struct sockaddr_in);

		int client_socket = accept4(server->listening_socket, (struct sockaddr*)&client_addr, &addrlen, SOCK_NONBLOCK);
		if (client_socket < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				// finished processing all incoming connections
				return;
			} else {
				// unexpected error in accepting the connection
				LOG_ERROR("accept failed: %s\n", strerror(errno));
				return;
			}
		}

		Connection* conn = connection_create(server->stats_enabled, server->blocklist, server->blocklist_len);
		conn->client_socket = client_socket;
		connection_set_client_hostport(conn, &client_addr);

		LOG_INFO("Received connection from %s\n", conn->client_hostport);

		// wait for client socket readability so we can read its CONNECT HTTP request
		if (poll_set_on_read_callback(p, client_socket, conn, true, false, (poll_callback)handle_client_connect_request_readability) < 0) {
			LOG_ERROR("failed to add accepted client socket from %s into poll instance: %s\n", conn->client_hostport, strerror(errno));

			connection_destroy(conn);
		}
	}
}

/**
 * @param read_fd
 * @param buf
 * @return the number of bytes read on success;
 * -1 when reading error is encountered;
 * -2 if the buffer is full.
 */
ssize_t read_into_buffer(int read_fd, TunnelBuffer* buf) {
	// We always want the contents in the buffer to be null terminated, even if no data is read
	//buf->write_ptr[0] = '\0';

	// Leave one byte for null terminator
	size_t remaining_capacity = BUFFER_SIZE - 1 - (buf->write_ptr - buf->start);
	if (remaining_capacity <= 0) {
		return -2;
	}

	ssize_t n_bytes_read = read(read_fd, buf->write_ptr, remaining_capacity);

	if (n_bytes_read <= 0) {
		return n_bytes_read;
	}

	buf->write_ptr += n_bytes_read;
	//buf->write_ptr[0] = '\0';
	return n_bytes_read;
}

int parse_http_connect_message(char* message, char** method_parsed, char** host_parsed, char** port_parsed, char** http_version_parsed) {
	// CONNECT google.com:443 HTTP/1.0
	// GET http://httpbin.org/get HTTP/1.1
	char* saveptr;
	char* method = strtok_r(message, " ", &saveptr);
	if (method == NULL) {
		return -1;
	}
	bool https;
	if (strcmp(method, "CONNECT") == 0) {
		https = true;
	} else if ((strcmp(method, "GET") == 0) 
		|| (strcmp(method, "POST") == 0) 
		|| (strcmp(method, "DELETE") == 0) 
		|| (strcmp(method, "HEAD") == 0) 
		|| (strcmp(method, "PATCH") == 0) 
		|| (strcmp(method, "OPTIONS") == 0))
	{
		https = false;
	} else {
		return -1;
	}
	char* host_port_token = strtok_r(NULL, " ", &saveptr);
	if (host_port_token == NULL) {
		return -1;
	}

	char* host_port_saveptr;
	char* default_port;
	if (https) {
		default_port = DEFAULT_HTTPS_PORT;
	} else {
		default_port = DEFAULT_HTTP_PORT;
		host_port_token += 7; // skip http://
		host_port_token = strtok_r(host_port_token, "/", &host_port_saveptr);
	}

	char* host;
	char* port;
	host = strtok_r(host_port_token, ":", &host_port_saveptr);
	port = strtok_r(NULL, ":", &host_port_saveptr);
	if (port == NULL) {
		port = default_port;
	}

	// HTTP/1.1 or HTTP/1.0
	char* http_version = strtok_r(NULL, " \r\n", &saveptr);
	if (http_version == NULL || (strcmp(http_version, "HTTP/1.0") != 0 && strcmp(http_version, "HTTP/1.1") != 0)) {
		return -1;
	}

	*method_parsed = method;
	*host_parsed = host;
	*port_parsed = port;
	*http_version_parsed = http_version;	

	LOG_DEBUG("method=%s host=%s, port=%s ver=%s\n", *method_parsed, *host_parsed, *port_parsed, *http_version_parsed);

	return https ? 1 : 0;
}

/**
 * @param conn
 * @return -1 if an error occurred and conn should be closed;
 * 0 if CONNECT was found and parsed;
 * 1 if we need to read more bytes.
 */
int read_connect_request(Connection* conn) {
	TunnelBuffer* buffer = &conn->to_target_buffer;
	ssize_t n_bytes_read = read_into_buffer(conn->client_socket, buffer);

	if (n_bytes_read < 0) {
		LOG_ERROR("reading for CONNECT from %s failed: %s, received %ld bytes\n", conn->client_hostport, strerror(errno), buffer->write_ptr - buffer->start);
		return -1;
	}

	if (n_bytes_read == 0) {
		LOG_INFO("client %s closed the connection before sending full http CONNECT message, received %ld bytes: %s\n", conn->client_hostport, buffer->write_ptr - buffer->start, buffer->start);
		return -1;
	}

	char* double_crlf = strstr(buffer->start, "\r\n\r\n");
	if (double_crlf != NULL) {
		// received full CONNECT message
		char *method, *host, *port, *http_version;
		char buf[4096];
		strncpy(buf, buffer->start, buffer->write_ptr - buffer->start);
		int ret = parse_http_connect_message(buf, &method, &host, &port, &http_version) ;
		if (ret < 0) {
			// malformed CONNECT
			LOG_ERROR("couldn't parse CONNECT message: %s\n", buffer->start);
			return -1;
		} else {
			strncpy(conn->target_host, host, MAX_HOST_LEN - 1);
			strncpy(conn->target_port, port, MAX_PORT_LEN - 1);
			strncpy(conn->http_version, http_version, HTTP_VERSION_LEN - 1);

			connection_set_target_hostport(conn);

			if(ret == 1){
				buffer->read_ptr = double_crlf + 4;  // skip over the double crlf
			} else {
				buffer->read_ptr = buffer->start;
				//buffer->write_ptr = buffer->start;
			}
			
			LOG_INFO("received CONNECT request: %s %s:%s\n", conn->http_version, conn->target_host, conn->target_port);
			conn->https = ret ? true:false;
			return 0;
		}
		
	}

	// we don't have an HTTP message yet, can we read more bytes?

	if (buffer->write_ptr >= buffer->start + BUFFER_SIZE - 1) {
		// no, the buffer is full
		LOG_ERROR("no CONNECT message from %s until buffer is full\n", conn->client_hostport);
		return -1;
	}

	// let's read more bytes
	return 1;
}

void handle_client_connect_request_readability(Poll* p, Connection* conn) {
	int result = read_connect_request(conn);
	if (result < 0) {
		connection_destroy(conn);
	} else if (result == 0) {
		// we have the full CONNECT message, let's connect to the target
		start_connecting_to_target(p, conn);
	} else {
		// need to read more bytes, wait for readability again
		if (poll_set_on_read_callback(p, conn->client_socket, conn, true, false, (poll_callback)handle_client_connect_request_readability) < 0) {
			LOG_ERROR("failed to re-add client socket from %s for reading CONNECT: %s\n", conn->client_hostport, strerror(errno));
			connection_destroy(conn);
		}
	}
}
