/* -*- Mode: C ; c-basic-offset: 2 -*- */
/*
 * netspeed: a program to generate network traffic
 * Copyright (C) 2013 Free Software Foundation, Inc
 *
 * Author: Nedko Arnaudov
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

/* C99 */
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <assert.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdarg.h>

/* POSIX */
#include <poll.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>
#include <signal.h>
#if !defined(NO_SCHED_FIFO)
#include <sched.h>
#endif

#define DEFAULT_WORKERS 4

#define DEFAULT_DL_RESOURCE "/speedtest/random4000x4000.jpg"
//#define DL_RESOURCE "/speedtest/random500x500.jpg"
#define DEFAULT_UL_RESOURCE "/speedtest/upload.php"
#define DEFAULT_UL_SIZE ((size_t)(3 * 1024 * 1024))

#define ABOUT "Generate network traffic. Written by Nedko Arnaudov."

/* OpenBSD */
#if !defined(MSG_NOSIGNAL)
#define MSG_NOSIGNAL 0
#endif

typedef int (* work_fn)(void * ctx, short revents, int * fd_ptr, short * events_ptr);
typedef void (* cleanup_fn)(void * ctx);

#define STATE_NOT_CONNECTED           0
#define STATE_CONNECTING              1
#define STATE_SENDING_REQUEST_HEADER  2
#define STATE_SENDING_REQUEST_BODY    3
#define STATE_READING_REPLY_HEADER    4
#define STATE_READING_REPLY_BODY      5
#define STATE_ERROR                  -1

struct connection
{
  int no;
  bool upload;
  const char * host;
  int state;
  int socket;
  uint32_t ip;                  /* network byte order */
  size_t offset;
  size_t size;
  char buffer[1024 * 1024];
};

#define LOGLVL_NO      -1
#define LOGLVL_FORCE    0
#define LOGLVL_ERROR    1
#define LOGLVL_WARNING  2
#define LOGLVL_INFO     3
#define LOGLVL_DEBUG1   4
#define LOGLVL_DEBUG2   5

#define LOGLVL_DEFAULT_MAX LOGLVL_WARNING

static int g_log_max = LOGLVL_DEFAULT_MAX;
static int g_progress = 0;
static size_t g_workers = DEFAULT_WORKERS;
static const char * g_dl_resource = DEFAULT_DL_RESOURCE;
static const char * g_ul_resource = DEFAULT_UL_RESOURCE;
static size_t g_ul_size = DEFAULT_UL_SIZE;

void log_msg(int level, const char * format, ...) __attribute__((format(printf, 2, 3)));
void log_msg(int level, const char * format, ...)
{
  va_list ap;

  if (level > g_log_max) return;

  va_start(ap, format);
  vfprintf(level > 0 ? stdout : stderr, format, ap);
  va_end(ap);
}

#define connection_ptr ((struct connection *)ctx)

#define LOG_MSG_(level, format, ...)             \
  log_msg(level, format "\n", ##__VA_ARGS__)
#define LOG_WORKER(level, no, format, ...)                \
  log_msg(level, "[%d] " format "\n", (int)(no), ##__VA_ARGS__)
#define LOG_WORKER_(level, format, ...)                         \
  LOG_WORKER(level, connection_ptr->no, format, ##__VA_ARGS__)

#define LFRC( format, ...) LOG_MSG(LOGLVL_FORCE,   format, ##__VA_ARGS__)
#define LERR( format, ...) LOG_MSG(LOGLVL_ERROR,   format, ##__VA_ARGS__)
#define LWRN( format, ...) LOG_MSG(LOGLVL_WARNING, format, ##__VA_ARGS__)
#define LINF( format, ...) LOG_MSG(LOGLVL_INFO,    format, ##__VA_ARGS__)
#define LDBG1(format, ...) LOG_MSG(LOGLVL_DEBUG1,  format, ##__VA_ARGS__)
#define LDBG2(format, ...) LOG_MSG(LOGLVL_DEBUG2,  format, ##__VA_ARGS__)

#define LOG_MSG LOG_WORKER_

int worker(void * ctx, short revents, int * fd_ptr, short * events_ptr)
{
  int ret, val;
  struct sockaddr_in sin;
  socklen_t len;
  ssize_t sret;
  size_t i;
  const char * ptr;
  char size_str[100];
  size_t size;

  LDBG2("state=%d", connection_ptr->state);

  switch (connection_ptr->state)
  {
  case STATE_NOT_CONNECTED:
    goto connect;
  case STATE_CONNECTING:
    assert((revents & POLLOUT) == POLLOUT);
    goto async_connect_done;
  case STATE_SENDING_REQUEST_HEADER:
  case STATE_SENDING_REQUEST_BODY:
    assert((revents & POLLOUT) == POLLOUT);
    if ((revents & (POLLERR | POLLHUP)) != 0)
    {
      LERR("async send fd error. revents=%#hx", revents);

      len = sizeof(val);
      ret = getsockopt(connection_ptr->socket, SOL_SOCKET, SO_ERROR, &val, &len);
      if (ret == -1)
      {
        LERR("getsockopt() failed to get socket send error. %d (%s)", errno, strerror(errno));
      }
      else
      {
        LERR("async send() error %d (%s)", val, strerror(val));
      }
      goto error;
    }
    goto send_request_continue;
  case STATE_READING_REPLY_HEADER:
    assert((revents & POLLIN) == POLLIN);
    if ((revents & (POLLERR | POLLHUP)) != 0)
    {
      LERR("async reply header recv fd error. revents=%#hx", revents);

      len = sizeof(val);
      ret = getsockopt(connection_ptr->socket, SOL_SOCKET, SO_ERROR, &val, &len);
      if (ret == -1)
      {
        LERR("getsockopt() failed to get socket recv error. %d (%s)", errno, strerror(errno));
      }
      else
      {
        LERR("async recv() error %d (%s)", val, strerror(val));
      }
      goto error;
    }
    goto read_reply_header;
  case STATE_READING_REPLY_BODY:
    assert((revents & POLLIN) == POLLIN);
    if ((revents & (POLLERR | POLLHUP)) != 0)
    {
      LERR("async reply body recv fd error. revents=%#hx", revents);

      len = sizeof(val);
      ret = getsockopt(connection_ptr->socket, SOL_SOCKET, SO_ERROR, &val, &len);
      if (ret == -1)
      {
        LERR("getsockopt() failed to get socket recv error. %d (%s)", errno, strerror(errno));
      }
      else
      {
        LERR("async recv() error %d (%s)", val, strerror(val));
      }
      goto error;
    }
    goto read_reply_body;
  default:
    assert(false);
    goto error;
  }

  assert(false);

connect:
  connection_ptr->socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (connection_ptr->socket == -1)
  {
    LERR("socket() failed. %d (%s)", errno, strerror(errno));
    goto error;
  }

  ret = fcntl(connection_ptr->socket, F_SETFL, O_NONBLOCK);
  if (ret == -1)
  {
    LERR("fcntl() failed to set socket non-blocking mode. %d (%s)", errno, strerror(errno));
    goto error;
  }


  sin.sin_family = AF_INET;
  sin.sin_port = htons(80);
  sin.sin_addr.s_addr = connection_ptr->ip;

  ret = connect(connection_ptr->socket, (struct sockaddr *)&sin, sizeof(struct sockaddr_in));
  if (ret == -1)
  {
    if (errno == EINPROGRESS)
    {
      connection_ptr->state = STATE_CONNECTING;
      *fd_ptr = connection_ptr->socket;
      *events_ptr = POLLOUT;
      return 1;
    }

    LERR("connect() failed. %d (%s)", errno, strerror(errno));
    goto error;
  }

  LINF("connect complete.");
  goto send_request;

async_connect_done:
  if ((revents & (POLLERR | POLLHUP)) != 0)
  {
    LERR("async connect failed. revents=%#hx", revents);
  }

  len = sizeof(val);
  ret = getsockopt(connection_ptr->socket, SOL_SOCKET, SO_ERROR, &val, &len);
  if (ret == -1)
  {
    LERR("getsockopt() failed to get socket connect error. %d (%s)", errno, strerror(errno));
    goto error;
  }
  if (val != 0)
  {
    LERR("async connect() failed. %d (%s)", val, strerror(val));
    goto error;
  }

  LINF("async connect complete.");

send_request:
  LINF("sending request header...");

  if (connection_ptr->upload)
  {
    snprintf(size_str, sizeof(size_str), "%zu", g_ul_size);
  }

  ret = snprintf(
    connection_ptr->buffer,
    sizeof(connection_ptr->buffer),
    "%s %s HTTP/1.1\r\n"
    "User-Agent: netspeed/0.0\r\n"
    "Accept: */*\r\n"
    "Host: %s\r\n"
    "%s%s%s"
    "\r\n",
    connection_ptr->upload ? "POST" : "GET",
    connection_ptr->upload ? g_ul_resource : g_dl_resource,
    connection_ptr->host,
    connection_ptr->upload ? "Content-Length: " : "",
    connection_ptr->upload ? size_str : "",
    connection_ptr->upload ? "\r\n" : "");
  if (ret < -1 || ret >= (int)sizeof(connection_ptr->buffer))
  {
    LERR("snprintf() failed compose request. %d", ret);
    goto error;
  }

  LDBG1("request-header:\n%s", connection_ptr->buffer);

  connection_ptr->state = STATE_SENDING_REQUEST_HEADER;
  connection_ptr->offset = 0;
  connection_ptr->size = (size_t)ret;

send_request_continue:
  while (connection_ptr->size > 0)
  {
    if (connection_ptr->state == STATE_SENDING_REQUEST_BODY &&
        connection_ptr->size >= sizeof(connection_ptr->buffer))
    {
      size = sizeof(connection_ptr->buffer);
    }
    else
    {
      size = connection_ptr->size;
    }

    sret = send(
      connection_ptr->socket,
      connection_ptr->buffer + connection_ptr->offset,
      size,
      MSG_NOSIGNAL);
    if (sret == -1)
    {
      if (errno == EINTR)
      {
        continue;
      }

      if (errno == EAGAIN || errno == EWOULDBLOCK)
      {
        *fd_ptr = connection_ptr->socket;
        *events_ptr = POLLOUT;
        return 1;
      }

      LERR("send() failed. %d (%s)", errno, strerror(errno));
      goto error;
    }

    if (connection_ptr->state == STATE_SENDING_REQUEST_HEADER)
    {
      connection_ptr->offset += sret;
    }

    connection_ptr->size -= sret;
  }

  if (connection_ptr->state == STATE_SENDING_REQUEST_HEADER)
  {
    LINF("request header sent");

    if (connection_ptr->upload)
    {
      connection_ptr->state = STATE_SENDING_REQUEST_BODY;
      connection_ptr->offset = 0;
      connection_ptr->size = g_ul_size;
      LINF("sending request body...");
      goto send_request_continue;
    }
  }
  else
  {
    LINF("request body sent");
  }

  connection_ptr->state = STATE_READING_REPLY_HEADER;
  connection_ptr->offset = 0;   /* parsed size */
  connection_ptr->size = 0;     /* read size */

read_reply_header:
  if (connection_ptr->size >= sizeof(connection_ptr->buffer))
  {
    LERR("HTTP reply header too big");
    goto error;
  }

  sret = recv(
    connection_ptr->socket,
    connection_ptr->buffer + connection_ptr->size,
    sizeof(connection_ptr->buffer) - connection_ptr->size,
    MSG_NOSIGNAL);
  if (sret == -1)
  {
    if (errno == EINTR)
    {
      goto read_reply_header;
    }

    if (errno == EAGAIN || errno == EWOULDBLOCK)
    {
      *fd_ptr = connection_ptr->socket;
      *events_ptr = POLLIN;
      return 1;
    }

    LERR("recv() failed. %d (%s)", errno, strerror(errno));
    goto error;
  }

  connection_ptr->size += sret;

  for (i = connection_ptr->offset; i + 3 < connection_ptr->size; i++)
  {
    if (connection_ptr->buffer[i    ] == '\r' &&
        connection_ptr->buffer[i + 1] == '\n' &&
        connection_ptr->buffer[i + 2] == '\r' &&
        connection_ptr->buffer[i + 3] == '\n')
    {
      connection_ptr->offset = i + 4;
      LINF("header size is %zu bytes", connection_ptr->offset);
      for (i = 0; i < connection_ptr->offset; i++)
      {
        if ((signed char)connection_ptr->buffer[i] < 0)
        {
          LERR("invalid char in HTTP reply header");
          goto error;
        }

        connection_ptr->buffer[i] = tolower(connection_ptr->buffer[i]);
      }

      connection_ptr->buffer[connection_ptr->offset] = 0;
      LDBG1("reply-header:\n%s", connection_ptr->buffer);

      /* calculate the size of body bytes we already read */
      i = connection_ptr->size - connection_ptr->offset;

      ptr = strstr(connection_ptr->buffer, "content-length");
      if (ptr == NULL)
      {
        goto unknown_size;
      }

      ptr += sizeof("content-length") - 1;

      while (*ptr == ' ') ptr++;

      if (*ptr != ':')
      {
        goto unknown_size;
      }
      ptr++;

      while (*ptr == ' ') ptr++;

      val = atoi(ptr);

      if (val > 0)
      {
        LINF("total body size is %d bytes", val);

        if ((size_t)val < i)
        {
          LERR("body bigger than announced");
          goto error;
        }

        /* substract the already received body bytes */
        connection_ptr->size = (size_t)val - i;
      }
      else
      {
      unknown_size:
       /* server didnt provide body size,
           assume body end will be marked by connection close */
        LWRN("unknown body size");
        goto error;
        connection_ptr->size = SIZE_MAX;
      }
      
      connection_ptr->state = STATE_READING_REPLY_BODY;
      connection_ptr->offset = i;
      goto read_reply_body;
    }
  }

  if (i >= 4)
  {
    /* next time don't parse the bytes already parsed */
    connection_ptr->offset = i - 4;
  }

  goto read_reply_header;

read_reply_body:
  while (connection_ptr->size > 0)
  {
    sret = recv(
      connection_ptr->socket,
      connection_ptr->buffer,
      sizeof(connection_ptr->buffer),
      MSG_NOSIGNAL);
    if (sret == -1)
    {
      if (errno == EINTR)
      {
        goto read_reply_header;
      }

      if (errno == EAGAIN || errno == EWOULDBLOCK)
      {
        *fd_ptr = connection_ptr->socket;
        *events_ptr = POLLIN;
        return 1;
      }

      LERR("recv() failed. %d (%s)", errno, strerror(errno));
      goto error;
    }

    connection_ptr->size -= sret;
    connection_ptr->offset += sret;
    if (g_progress > 0)
    {
      if (g_progress == 1)
      {
        printf(".");
      }
      else
      {
        printf("(%zd)", sret);
      }

      fflush(stdout);
    }
  }

  LINF("%zu body bytes read", connection_ptr->offset);
  goto send_request;
  //return 0;                     /* done */

error:
  connection_ptr->state = STATE_ERROR;
  return -1;
}

void connection_cleanup(void * ctx)
{
  if (connection_ptr->socket != -1)
  {
    LINF("closing socket...");
    close(connection_ptr->socket);
  }
}

#undef connection_ptr
#undef LOG_MSG
#define LOG_MSG LOG_MSG_

uint32_t resolve_host(const char * hostname)
{
  struct hostent * he_ptr;

  he_ptr = gethostbyname(hostname);
  if (he_ptr == NULL)
  {
    LERR("Cannot resolve \"%s\". h_errno is %d", hostname, h_errno);
    return 0;
  }

  return *(uint32_t *)(he_ptr->h_addr);
}

bool
create_worker(
  int worker_no,
  const char * type,
  uint32_t ip,
  const char * hostname,
  void ** ctx,
  work_fn * work,
  cleanup_fn * cleanup)
{
  struct connection * connection_ptr;
  bool upload;

  if (strcmp(type, "d") == 0)
  {
    upload = false;
  }
  else if (strcmp(type, "u") == 0)
  {
    upload = true;
  }
  else
  {
    LOG_WORKER(LOGLVL_ERROR, worker_no, "unknown type \"%s\".", type);
    return false;
  }

  LOG_WORKER(LOGLVL_INFO, worker_no, "connecting to %s for %s", hostname, upload ? "uploading" : "downloading");

  connection_ptr = malloc(sizeof(struct connection));
  if (connection_ptr == NULL)
  {
    LOG_WORKER(LOGLVL_ERROR, worker_no, "memory allocation failed.");
    return false;
  }

  connection_ptr->no = worker_no;
  connection_ptr->upload = upload;
  connection_ptr->host = hostname;
  connection_ptr->state = STATE_NOT_CONNECTED;
  connection_ptr->socket = -1;
  connection_ptr->ip = ip;

  *ctx = connection_ptr;
  *work = worker;
  *cleanup = connection_cleanup;

  return true;
}

#if !defined(NO_SCHED_FIFO)
static bool disable_preemption(int priority)
{
  struct sched_param sched_param;

  sched_param.sched_priority = priority;
  if (sched_setscheduler(0, SCHED_FIFO, &sched_param) != 0)
  {
    LERR("Cannot set scheduling policy %d (%s)", errno, strerror(errno));
    return false;
  }

  return true;
}
#endif

int main(int argc, char ** argv)
{
  int ret;
  uint32_t ip;
  struct worker
  {
    void * ctx;
    work_fn work;
    cleanup_fn cleanup;
    struct pollfd pollfd;
  };
  struct worker * workers = NULL;
  struct pollfd * pollfds = NULL;
  int nfds, poll_index;
  size_t i;
  bool worker_count_supplied = false;
  size_t workers_per_host;
  int host_index;

  argc--; argv++;

  /* process options */
  while (argc > 0 && **argv == '-')
  {
    if (strcmp(*argv, "-v") == 0)
    {
      g_log_max++;
    }
    else if (strcmp(*argv, "-q") == 0)
    {
      g_log_max--;
    }
    else if (strcmp(*argv, "-s") == 0)
    {
      g_log_max = -1;
    }
    else if (strcmp(*argv, "-p") == 0)
    {
      g_progress++;
    }
    else if (strcmp(*argv, "--help") == 0)
    {
      goto help;
    }
    else if (strcmp(*argv, "-w") == 0 && argc >= 2)
    {
      i = atoi(argv[1]);
      if (i < 1)
      {
        LERR("Bad value for workers option");
        goto optfail;
      }

      g_workers = i;
      worker_count_supplied = true;
      argc--; argv++;
    }
    else if (strcmp(*argv, "-u") == 0 && argc >= 2)
    {
      i = atoi(argv[1]);
      if (i < 1)
      {
        LERR("Bad value for upload size option");
        goto optfail;
      }

      g_ul_size = i;
      argc--; argv++;
    }
    else
    {
      LWRN("Ignoring unknown option %s", *argv);
    }

    //printf("log level max is %d\n", g_log_max);
    argc--; argv++;
  }

  if (argc == 0 || (argc % 2) != 0)
  {
  help:
    LFRC(ABOUT);
    LFRC("Usage: netspeed [options] <type> <host> [<type> <host>] ...");
    LFRC("");
    LFRC("Options:");
    LFRC("  -v Increase verbosity. May be used more than once.");
    LFRC("  -q Decrease verbosity. May be used more than once.");
    LFRC("  -s Be completely silent.");
    LFRC("  -p Print progress (dots). Use twice for printing chunk sizes.");
    LFRC("  -w <num> Worker count (per type/host pair).");
    LFRC("  -u <num> Upload size. Ignored when downloading.");
    LFRC("  --help Shows this help text");
    LFRC("");
    LFRC("  <type> is either 'u' (upload) or 'd' (download)");
    LFRC("  <host> is a ookla speedtest host");
    ret = 0;
    goto exit;
  }

  LFRC(ABOUT);
  if (g_log_max != LOGLVL_DEFAULT_MAX)
  {
    LFRC("log level max is %d", g_log_max);
  }

  if (argc > 2)
  {
    workers_per_host = worker_count_supplied ? g_workers : 1;

    LFRC("%zu worker(s) per host", workers_per_host);

    g_workers = workers_per_host * (argc / 2);

    LFRC("%zu total worker(s)", g_workers);
  }
  else
  {
    workers_per_host = g_workers;
    LFRC("%zu worker(s)", g_workers);
  }

  LFRC("POST body size: %zu bytes", g_ul_size);
  //LFRC("download resource: %s", g_dl_resource);
  //LFRC("upload resource: %s", g_ul_resource);

  workers = calloc(g_workers, sizeof(struct worker));
  if (workers == NULL)
  {
    LERR("memory allocation failed. (workers)");
    ret = 1;
    goto free;
  }

  pollfds = calloc(g_workers, sizeof(struct pollfd));
  if (pollfds == NULL)
  {
    LERR("memory allocation failed. (pollfds)");
    ret = 1;
    goto free;
  }

  if (signal(SIGPIPE, SIG_IGN) == SIG_ERR)
  {
    LERR("Cannot ignore SIGPIPE. %d (%s)", errno, strerror(errno));
    goto fail;
  }

  host_index = 0;
  while (argc > 0)
  {
    assert(argc >= 2);
    assert(argc % 2 == 0);

    ip = resolve_host(argv[1]);
    if (ip == 0)
    {
      goto fail;
    }

    for (i = host_index * workers_per_host; i < (host_index + 1) * workers_per_host; i++)
    {
      if (!create_worker(
            i,
            argv[0],
            ip,
            argv[1],
            &workers[i].ctx,
            &workers[i].work,
            &workers[i].cleanup))
      {
        g_workers = 0;
        goto fail;
      }

      workers[i].pollfd.fd = -1;
      workers[i].pollfd.revents = 0;
    }

    host_index++;
    argc -= 2;
    argv += 2;
  }

  ret = mlockall(MCL_CURRENT | MCL_FUTURE);
  if (ret == -1)
  {
    LERR("mlockall() failed. %d (%s)", errno, strerror(errno));
    //goto fail;
  }

#if !defined(NO_SCHED_FIFO)
  if (!disable_preemption(10))
  {
    //goto fail;
  }
#endif

  poll_index = 0;
loop:
  assert(poll_index == 0);
  for (i = 0; i < g_workers; i++)
  {
    if (workers[i].work != NULL)
    {
      if (workers[i].pollfd.fd == -1 || /* first time */
          workers[i].pollfd.revents != 0) /* or when there are pending events */
      {
        ret = workers[i].work(
          workers[i].ctx,
          workers[i].pollfd.revents,
          &workers[i].pollfd.fd,
          &workers[i].pollfd.events);
        if (ret < 0)
        {
          ret = -ret;
          goto cleanup;
        }

        if (ret == 0)
        {
          /* worker done */
          workers[i].work = NULL;
          LOG_WORKER(LOGLVL_INFO, i, "worker done");
          continue;
        }

        workers[i].pollfd.revents = 0;

        assert(workers[i].pollfd.fd != -1);
        assert(workers[i].pollfd.events != 0);
        LOG_WORKER(LOGLVL_DEBUG2, i, "worker waits on %d\n", workers[i].pollfd.fd);
      }
      else
      {
        LOG_WORKER(LOGLVL_DEBUG2, i, "worker still waits on %d\n", workers[i].pollfd.fd);
      }

      pollfds[poll_index].fd = workers[i].pollfd.fd;
      pollfds[poll_index].events = workers[i].pollfd.events;
      pollfds[poll_index].revents = 0;
      poll_index++;
    }
  }

  if (poll_index == 0)
  {
    ret = 0;
    LINF("no more workers");
    goto cleanup;
  }

  nfds = poll_index;
  LDBG2("polling %d fds", nfds);
  ret = poll(pollfds, nfds, -1);
  LDBG2("poll() returns %d", ret);
  if (ret == -1)
  {
    LERR("poll() failed. %d (%s)", errno, strerror(errno));
    goto fail;
  }

  assert(ret > 0);
  poll_index = 0;
  while (ret > 0)
  {
    assert(poll_index < nfds);
    if (pollfds[poll_index].revents != 0)
    {
      for (i = 0; i < g_workers; i++)
      {
        if (workers[i].work != NULL &&
            workers[i].pollfd.fd == pollfds[poll_index].fd)
        {
          workers[i].pollfd.revents = pollfds[poll_index].revents;
          assert(workers[i].pollfd.revents != 0);
          break;
        }
      }
      assert(i < g_workers);        /* fd/worker not found */
      ret--;
    }
    poll_index++;
  }
  poll_index = 0;
  goto loop;

fail:
  ret = 1;
cleanup:
  for (i = 0; i < g_workers; i++)
  {
    if (workers[i].cleanup != NULL)
    {
      workers[i].cleanup(workers[i].ctx);
    }
  }
free:
  free(workers);
  free(pollfds);
exit:
  return ret;
optfail:
  ret = 1;
  goto exit;
}
