#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include "../log.h"
#include "../poll.h"
#include "../util.h"
#include "connection.h"

// Represents a (uni-directional) link between source and destination.
// The link alternates between two states:
// 1. reading from source
// 2. writing to destination

typedef struct tagTunnelingLink {
	Connection* conn;
	int read_fd;
	int write_fd;
	TunnelBuffer* buf;
	const char* source_hostport;
	const char* dst_hostport;
}Link;

void setup_link_wait_to_read(Poll* p, Link* link);
void setup_link_wait_to_write(Poll* p, Link* link);
void handle_link_readability(Poll* p, Link* link);
void handle_link_writability(Poll* p, Link* link);

void setup_tunneling_from_target_to_client(Poll* p, Connection* conn) {
	Link* link = malloc(sizeof(Link));
	link->conn = conn;
	link->read_fd = conn->target_socket;
	link->write_fd = conn->client_socket_dup;
	link->buf = &conn->to_client_buffer;
	link->source_hostport = conn->target_hostport;
	link->dst_hostport = conn->client_hostport;

	// First, send HTTP 200 to client
	if(conn->https){
		int bytes = sprintf(conn->to_client_buffer.start, "%s 200 Connection Established \r\n\r\n", conn->http_version);
		conn->to_client_buffer.write_ptr += bytes;
		setup_link_wait_to_write(p, link);
	} else {
		setup_link_wait_to_read(p, link);
	}
}

void setup_tunneling_from_client_to_target(Poll* p, Connection* conn) {

	Link* link = malloc(sizeof(Link));
	link->conn = conn;
	link->read_fd = conn->client_socket;
	link->write_fd = conn->target_socket_dup;
	link->buf = &conn->to_target_buffer;
	link->source_hostport = conn->client_hostport;
	link->dst_hostport = conn->target_hostport;
	if(conn->https){
		size_t bytes_remaining = conn->to_target_buffer.write_ptr - conn->to_target_buffer.read_ptr;
		if (bytes_remaining > 0) {
			// if we received more than just the CONNECT message from the client, send the rest of the bytes to the target
			LOG_INFO("sending %lu left over bytes after CONNECT\n", bytes_remaining);
			setup_link_wait_to_write(p, link);
			
		} else {
			tunnel_buffer_reset(&conn->to_target_buffer);
			setup_link_wait_to_read(p, link);
		}
	} else {
		size_t bytes_remaining = conn->to_target_buffer.write_ptr - conn->to_target_buffer.start;
		if (bytes_remaining > 0) {
			// if we received more than just the CONNECT message from the client, send the rest of the bytes to the target
			LOG_INFO("forwarding %lu bytes client request to target \n", bytes_remaining);
			setup_link_wait_to_write(p, link);
		} else {
			tunnel_buffer_reset(&conn->to_target_buffer);
			setup_link_wait_to_read(p, link);
		}
	}
}

void start_tunneling(struct Poll* p, Connection* conn) {
	// dup each socket to decouple read and write ends of the socket
	// this allows us to wait for its readability and writability separately
	// use the original fd for reading; use the dupped fd for writing
	conn->client_socket_dup = dup(conn->client_socket);
	conn->target_socket_dup = dup(conn->target_socket);

	// set up a tunneling link for both directions
	setup_tunneling_from_target_to_client(p, conn);
	setup_tunneling_from_client_to_target(p, conn);
}

void setup_link_wait_to_read(struct Poll* p, Link* link) {
	if (poll_set_on_read_callback(p, link->read_fd, link, true, false, (poll_callback)handle_link_readability) < 0) {
		LOG_ERROR("failed to wait on read_fd of (%s) -> (%s) for readability: %s\n", link->source_hostport, link->dst_hostport, strerror(errno));
		connection_destroy(link->conn);
		free(link);
		return;
	}
}

void setup_link_wait_to_write(struct Poll* p, Link* link) {
	if (poll_set_on_write_callback(p, link->write_fd, link, true, false, (poll_callback)handle_link_writability) < 0) {
		LOG_ERROR("failed to wait on write_fd of (%s) -> (%s) for writability: %s\n", link->source_hostport, link->dst_hostport, strerror(errno));
		connection_destroy(link->conn);
		free(link);
		return;
	}
}

void handle_link_readability(Poll* p, Link* link) {
	size_t remaining_capacity = BUFFER_SIZE - (link->buf->write_ptr - link->buf->start);
	if (remaining_capacity <= 0) {
		die(hsprintf("going to read for tunnel (%s) -> (%s), but the buf is full; this should not happen\n", link->source_hostport, link->dst_hostport));
	}

	ssize_t n_bytes_read = read(link->read_fd, link->buf->write_ptr, remaining_capacity);

	if (n_bytes_read == 0) {
		// peer stopped sending
		LOG_INFO("peer (%s) -> (%s) closed connection\n", link->source_hostport, link->dst_hostport);
		shutdown(link->read_fd, SHUT_RD);
		shutdown(link->write_fd, SHUT_WR);
		if (++link->conn->halves_closed == 2) {
			LOG_INFO("tunnel (%s) -> (%s) closed", link->conn->client_hostport, link->conn->target_hostport);
			// both halves closed, tear down the whole connection
			connection_destroy(link->conn);
			free(link);
		}
		return;
	} else if (n_bytes_read < 0) {
		// read error
		LOG_ERROR("read error from (%s) -> (%s): %s\n", link->source_hostport, link->dst_hostport, strerror(errno));

		connection_destroy(link->conn);
		free(link);
		return;
	}

	LOG_DEBUG("received %zu bytes (%s) -> (%s)\n", n_bytes_read, link->source_hostport, link->dst_hostport);
	link->buf->write_ptr += n_bytes_read;
	link->conn->n_bytes_transferred += n_bytes_read;

	// we will then write into write_fd
	setup_link_wait_to_write(p, link);
}

void handle_link_writability(struct Poll* p, Link* link) {
	size_t n_bytes_to_send = link->buf->write_ptr - link->buf->read_ptr;

	if (n_bytes_to_send <= 0) {
		//die(hsprintf("going to write for tunnel (%s) -> (%s), but the buf is empty; this should not happen\n", link->source_hostport, link->dst_hostport));
		LOG_ERROR("going to write for tunnel (%s) -> (%s), but the buf is empty; this should not happen\n", link->source_hostport, link->dst_hostport);
	}

	ssize_t bytes_sent = send(link->write_fd, link->buf->read_ptr, n_bytes_to_send, MSG_NOSIGNAL);

	if (bytes_sent < 0) {
		// peer refused to receive?
		// teardown the entire connection
		LOG_ERROR("write error from (%s) -> (%s): %s\n", link->source_hostport, link->dst_hostport, strerror(errno));

		connection_destroy(link->conn);
		free(link);
		return;
	}

	LOG_DEBUG("wrote %zu bytes (%s) -> (%s)\n", bytes_sent, link->source_hostport, link->dst_hostport);

	link->buf->read_ptr += bytes_sent;

	if (link->buf->read_ptr >= link->buf->write_ptr) {
		// sent everything, we can read again
		link->buf->read_ptr = link->buf->write_ptr = link->buf->start;

		setup_link_wait_to_read(p, link);
	} else {
		// We didn't manage to send all the bytes.
		// This can happen when the TCP buffer is full for a slow receiver.
		// Wait for writability to send again later.
		setup_link_wait_to_write(p, link);
	}
}
