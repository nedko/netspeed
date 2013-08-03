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

#define WORKERS 2

#define DL_RESOURCE "/speedtest/random4000x4000.jpg"
//#define DL_RESOURCE "/speedtest/random500x500.jpg"
#define UL_RESOURCE "/speedtest/upload.php"
#define UL_SIZE (30 * 1024 * 1024)

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

#define connection_ptr ((struct connection *)ctx)

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

  //printf("[%d] state=%d\n", connection_ptr->no, connection_ptr->state);

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
      fprintf(stderr, "[%d] async send fd error. revents=%#hx\n", connection_ptr->no, revents);

      len = sizeof(val);
      ret = getsockopt(connection_ptr->socket, SOL_SOCKET, SO_ERROR, &val, &len);
      if (ret == -1)
      {
        fprintf(stderr, "[%d] getsockopt() failed to get socket send error. %d (%s)\n", connection_ptr->no, errno, strerror(errno));
      }
      else
      {
        fprintf(stderr, "[%d] async send() error %d (%s)\n", connection_ptr->no, val, strerror(val));
      }
      goto error;
    }
    goto send_request_continue;
  case STATE_READING_REPLY_HEADER:
    assert((revents & POLLIN) == POLLIN);
    if ((revents & (POLLERR | POLLHUP)) != 0)
    {
      fprintf(stderr, "[%d] async reply header recv fd error. revents=%#hx\n", connection_ptr->no, revents);

      len = sizeof(val);
      ret = getsockopt(connection_ptr->socket, SOL_SOCKET, SO_ERROR, &val, &len);
      if (ret == -1)
      {
        fprintf(stderr, "[%d] getsockopt() failed to get socket recv error. %d (%s)\n", connection_ptr->no, errno, strerror(errno));
      }
      else
      {
        fprintf(stderr, "[%d] async recv() error %d (%s)\n", connection_ptr->no, val, strerror(val));
      }
      goto error;
    }
    goto read_reply_header;
  case STATE_READING_REPLY_BODY:
    assert((revents & POLLIN) == POLLIN);
    if ((revents & (POLLERR | POLLHUP)) != 0)
    {
      fprintf(stderr, "[%d] async reply body recv fd error. revents=%#hx\n", connection_ptr->no, revents);

      len = sizeof(val);
      ret = getsockopt(connection_ptr->socket, SOL_SOCKET, SO_ERROR, &val, &len);
      if (ret == -1)
      {
        fprintf(stderr, "[%d] getsockopt() failed to get socket recv error. %d (%s)\n", connection_ptr->no, errno, strerror(errno));
      }
      else
      {
        fprintf(stderr, "[%d] async recv() error %d (%s)\n", connection_ptr->no, val, strerror(val));
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
    fprintf(stderr, "[%d] socket() failed. %d (%s)\n", connection_ptr->no, errno, strerror(errno));
    goto error;
  }

  ret = fcntl(connection_ptr->socket, F_SETFL, O_NONBLOCK);
  if (ret == -1)
  {
    fprintf(stderr, "[%d] fcntl() failed to set socket non-blocking mode. %d (%s)\n", connection_ptr->no, errno, strerror(errno));
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

    fprintf(stderr, "[%d] connect() failed. %d (%s)\n", connection_ptr->no, errno, strerror(errno));
    goto error;
  }

  printf("[%d] connect complete.\n", connection_ptr->no);
  goto send_request;

async_connect_done:
  if ((revents & (POLLERR | POLLHUP)) != 0)
  {
    fprintf(stderr, "[%d] async connect failed. revents=%#hx\n", connection_ptr->no, revents);
  }

  len = sizeof(val);
  ret = getsockopt(connection_ptr->socket, SOL_SOCKET, SO_ERROR, &val, &len);
  if (ret == -1)
  {
    fprintf(stderr, "[%d] getsockopt() failed to get socket connect error. %d (%s)\n", connection_ptr->no, errno, strerror(errno));
    goto error;
  }
  if (val != 0)
  {
    fprintf(stderr, "[%d] async connect() failed. %d (%s)\n", connection_ptr->no, val, strerror(val));
    goto error;
  }

  printf("[%d] async connect complete.\n", connection_ptr->no);

send_request:
  printf("[%d] sending request header...\n", connection_ptr->no);

  if (connection_ptr->upload)
  {
    snprintf(size_str, sizeof(size_str), "%zu", UL_SIZE);
  }

  ret = snprintf(
    connection_ptr->buffer,
    sizeof(connection_ptr->buffer),
    "%s HTTP/1.1\r\n"
    "User-Agent: netspeed/0.0\r\n"
    "Accept: */*\r\n"
    "Host: %s\r\n"
    "%s%s%s"
    "\r\n",
    connection_ptr->upload ? "POST " UL_RESOURCE : "GET " DL_RESOURCE,
    connection_ptr->host,
    connection_ptr->upload ? "Content-Length: " : "",
    connection_ptr->upload ? size_str : "",
    connection_ptr->upload ? "\r\n" : "");
  if (ret < -1 || ret >= (int)sizeof(connection_ptr->buffer))
  {
    fprintf(stderr, "[%d] snprintf() failed compose request. %d\n", connection_ptr->no, ret);
    goto error;
  }

  //printf("[%d] request-header:\n%s\n", connection_ptr->no, connection_ptr->buffer);

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

      fprintf(stderr, "[%d] send() failed. %d (%s)\n", connection_ptr->no, errno, strerror(errno));
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
    printf("[%d] request header sent\n", connection_ptr->no);

    if (connection_ptr->upload)
    {
      connection_ptr->state = STATE_SENDING_REQUEST_BODY;
      connection_ptr->offset = 0;
      connection_ptr->size = UL_SIZE;
      printf("[%d] sending request body...\n", connection_ptr->no);
      goto send_request_continue;
    }
  }
  else
  {
    printf("[%d] request body sent\n", connection_ptr->no);
  }

  connection_ptr->state = STATE_READING_REPLY_HEADER;
  connection_ptr->offset = 0;   /* parsed size */
  connection_ptr->size = 0;     /* read size */

read_reply_header:
  if (connection_ptr->size >= sizeof(connection_ptr->buffer))
  {
    fprintf(stderr, "[%d] HTTP reply header too big\n", connection_ptr->no);
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

    fprintf(stderr, "[%d] recv() failed. %d (%s)\n", connection_ptr->no, errno, strerror(errno));
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
      printf("[%d] header size is %zu bytes\n", connection_ptr->no, connection_ptr->offset);
      for (i = 0; i < connection_ptr->offset; i++)
      {
        if (connection_ptr->buffer[i] < 0)
        {
          fprintf(stderr, "[%d] invalid char in HTTP reply header\n", connection_ptr->no);
          goto error;
        }

        connection_ptr->buffer[i] = tolower(connection_ptr->buffer[i]);
      }

      connection_ptr->buffer[connection_ptr->offset] = 0;
      //printf("[%d] reply-header:\n%s\n", connection_ptr->no, connection_ptr->buffer);

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
        printf("[%d] total body size is %d bytes\n", connection_ptr->no, val);

        if ((size_t)val < i)
        {
          fprintf(stderr, "[%d] body bigger than announced\n", connection_ptr->no);
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
        printf("[%d] unknown body size\n", connection_ptr->no);
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

      fprintf(stderr, "[%d] recv() failed. %d (%s)\n", connection_ptr->no, errno, strerror(errno));
      goto error;
    }

    connection_ptr->size -= sret;
    connection_ptr->offset += sret;
    //printf("(%zd)", sret); fflush(stdout);
  }

  printf("[%d] %zu body bytes read\n", connection_ptr->no, connection_ptr->offset);
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
    printf("[%d] closing socket...\n", connection_ptr->no);
    close(connection_ptr->socket);
  }
}

#undef connection_ptr

uint32_t resolve_host(const char * hostname)
{
  struct hostent * he_ptr;

  he_ptr = gethostbyname(hostname);
  if (he_ptr == NULL)
  {
    fprintf(stderr, "Cannot resolve \"%s\". h_errno is %d\n", hostname, h_errno);
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
    fprintf(stderr, "[%d] unknown type \"%s\".\n", worker_no, type);
    return false;
  }

  printf("[%d] connecting to %s\n", worker_no, hostname);

  connection_ptr = malloc(sizeof(struct connection));
  if (connection_ptr == NULL)
  {
    fprintf(stderr, "[%d] memory allocation failed.\n", worker_no);
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
  } workers[WORKERS];
  struct pollfd pollfds[WORKERS];
  int i, nfds, poll_index;

  printf("Generate network traffic. Written by Nedko Arnaudov.\n");

  if (argc < 2)
  {
    printf("Usage: netspeed <type> <host>\n");
    printf("<type> is either 'u' (upload) or 'd' (download)\n");
    printf("<host> is a ookla speedtest host\n");
    ret = 0;
    goto exit;
  }

  ret = mlockall(MCL_FUTURE);
  if (ret == -1)
  {
    fprintf(stderr, "mlockall() failed. %d (%s)\n", errno, strerror(errno));
    goto fail;
  }

  ip = resolve_host(argv[2]);
  if (ip == 0)
  {
    goto fail;
  }

  for (i = 0; i < WORKERS; i++)
  {
    workers[i].cleanup = NULL;
  }

  for (i = 0; i < WORKERS; i++)
  {
    if (!create_worker(
          i,
          argv[1],
          ip,
          argv[2],
          &workers[i].ctx,
          &workers[i].work,
          &workers[i].cleanup))
    {
      goto fail;
    }

    workers[i].pollfd.fd = -1;
    workers[i].pollfd.revents = 0;
  }

  poll_index = 0;
loop:
  assert(poll_index == 0);
  for (i = 0; i < WORKERS; i++)
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
          printf("worker done\n");
          continue;
        }

        workers[i].pollfd.revents = 0;

        assert(workers[i].pollfd.fd != -1);
        assert(workers[i].pollfd.events != 0);
        //printf("[%d] worker waits on %d\n", i, workers[i].pollfd.fd);
      }
      else
      {
        //printf("[%d] worker still waits on %d\n", i, workers[i].pollfd.fd);
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
    printf("no more workers\n");
    goto cleanup;
  }

  nfds = poll_index;
  //printf("polling %d fds\n", nfds);
  ret = poll(pollfds, nfds, -1);
  //printf("poll() returns %d\n", ret);
  if (ret == -1)
  {
    fprintf(stderr, "poll() failed. %d (%s)\n", errno, strerror(errno));
    goto fail;
  }

  assert(ret > 0);
  poll_index = 0;
  while (ret > 0)
  {
    assert(poll_index < nfds);
    if (pollfds[poll_index].revents != 0)
    {
      for (i = 0; i < WORKERS; i++)
      {
        if (workers[i].work != NULL &&
            workers[i].pollfd.fd == pollfds[poll_index].fd)
        {
          workers[i].pollfd.revents = pollfds[poll_index].revents;
          assert(workers[i].pollfd.revents != 0);
          break;
        }
      }
      assert(i < WORKERS);        /* fd/worker not found */
      ret--;
    }
    poll_index++;
  }
  poll_index = 0;
  goto loop;

fail:
  ret = 1;
cleanup:
  for (i = 0; i < WORKERS; i++)
  {
    workers[i].cleanup(workers[i].ctx);
  }
exit:
  return ret;
}
