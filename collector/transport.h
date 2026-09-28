// SPDX-License-Identifier: MIT
// Bounded nonblocking transport; independently exercised without loading BPF.
#ifndef MONITOR_TRANSPORT_H
#define MONITOR_TRANSPORT_H
#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

// Bounded burst reserve. Roughly 16 MiB of JSON frames at typical open-event
// size; sustained overload still increments queue_lost rather than blocking BPF.
#define QUEUE_CAP 16384
struct message { char *data; size_t size, offset; };
static struct message queue[QUEUE_CAP];
static unsigned head, used;
static unsigned long long queue_lost, transport_disconnects;
static const char *socket_path;
static int sock = -1, transport_error;
static bool draining;
static unsigned long long drain_deadline;

static unsigned long long transport_now_ns(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (unsigned long long)t.tv_sec * 1000000000ULL + t.tv_nsec;
}
static void flush_queue(void) {
    if (!socket_path || !used || transport_error) return;
    if (sock < 0) {
        sock = socket(AF_UNIX, SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC, 0);
        if (sock < 0) return;
        struct sockaddr_un addr = {.sun_family=AF_UNIX};
        if (strlen(socket_path) >= sizeof(addr.sun_path)) {
            transport_error = -ENAMETOOLONG;
            close(sock); sock = -1; return;
        }
        strcpy(addr.sun_path, socket_path);
        if (connect(sock, (void *)&addr, sizeof(addr)) < 0) {
            close(sock); sock = -1; return;
        }
    }
    while (used) {
        struct message *m = &queue[head];
        ssize_t n = send(sock, m->data + m->offset, m->size - m->offset, MSG_NOSIGNAL);
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) return;
        if (n <= 0) {
            transport_disconnects++;
            if (draining) transport_error = -EPIPE;
            close(sock); sock = -1; m->offset = 0; return;
        }
        m->offset += (size_t)n;
        if (m->offset < m->size) return;
        free(m->data); memset(m, 0, sizeof(*m));
        head = (head + 1) % QUEUE_CAP; used--;
    }
}
static int transport_wait(short events) {
    unsigned long long now = transport_now_ns();
    if (now >= drain_deadline) return -ETIMEDOUT;
    unsigned long long left_ms = (drain_deadline - now + 999999) / 1000000;
    int ms = (int)(left_ms < 20 ? left_ms : 20);
    struct pollfd p = {.fd=sock, .events=events};
    int rc = poll(sock < 0 ? NULL : &p, sock < 0 ? 0 : 1, ms);
    return rc < 0 && errno != EINTR ? -errno : 0;
}
static void transport_begin_shutdown(unsigned timeout_ms) {
    draining = true;
    drain_deadline = transport_now_ns() + (unsigned long long)timeout_ms * 1000000ULL;
}
static int transport_drain(void) {
    while (used && !transport_error) {
        flush_queue();
        if (!used || transport_error) break;
        int rc = transport_wait(POLLOUT);
        if (rc) return rc;
    }
    return transport_error;
}
static void queue_message(char *data, size_t len) {
    if (!socket_path) {
        if (fwrite(data, 1, len, stdout) != len || fputc('\n', stdout) == EOF)
            transport_error = -EIO;
        free(data); return;
    }
    if (used == QUEUE_CAP) {
        if (draining) {
            int rc = transport_drain();
            if (rc) transport_error = rc;
        } else flush_queue();
    }
    if (used == QUEUE_CAP || transport_error) { queue_lost++; free(data); return; }
    char *frame = malloc(len + 4);
    if (!frame) {
        queue_lost++;
        if (draining) transport_error = -ENOMEM;
        free(data); return;
    }
    uint32_t size = htonl((uint32_t)len);
    memcpy(frame, &size, 4); memcpy(frame + 4, data, len); free(data);
    queue[(head + used) % QUEUE_CAP] = (struct message){frame, len + 4, 0};
    used++;
    flush_queue();
}
// The peer acknowledges only after EOF, frame validation and persistent flush.
// Sending all bytes to a socket alone is not an acknowledgement of processing.
static int transport_finish(const char *event_id) {
    int rc = transport_drain();
    if (rc) return rc;
    if (!socket_path) return fflush(stdout) ? -EIO : 0;
    if (sock < 0 || shutdown(sock, SHUT_WR)) return -EPIPE;
    char expected[512], reply[512];
    int size = snprintf(expected, sizeof(expected), "COMMITTED %s\n", event_id);
    if (size < 0 || (size_t)size >= sizeof(expected)) return -EINVAL;
    size_t received = 0;
    while (received < sizeof(reply)) {
        rc = transport_wait(POLLIN);
        if (rc) return rc;
        ssize_t n = recv(sock, reply + received, sizeof(reply) - received, 0);
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) continue;
        if (n <= 0) return -EPIPE;
        received += (size_t)n;
        if (received > (size_t)size || memcmp(reply, expected, received)) return -EPROTO;
        if (received == (size_t)size) return 0;
    }
    return -EPROTO;
}
static void transport_cleanup(void) {
    if (sock >= 0) close(sock);
    for (unsigned i = 0; i < used; i++) free(queue[(head + i) % QUEUE_CAP].data);
}
#endif
