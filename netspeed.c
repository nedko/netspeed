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

/* OpenBSD */
#if !defined(MSG_NOSIGNAL)
#define MSG_NOSIGNAL 0
#endif

typedef int (* work_fn)(void * ctx, short revents, int * fd_ptr, short * events_ptr);
typedef void (* cleanup_fn)(void * ctx);

#define STATE_NOT_CONNECTED           0
#define STATE_CONNECTING              1
#define STATE_SENDING_REQUEST         2
#define STATE_READING_REPLY_HEADER    3
#define STATE_READING_REPLY_BODY      4
#define STATE_ERROR                  -1

struct connection
{
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

  switch (connection_ptr->state)
  {
  case STATE_NOT_CONNECTED:
    goto connect;
  case STATE_CONNECTING:
    assert((revents & POLLOUT) == POLLOUT);
    goto async_connect_done;
  case STATE_SENDING_REQUEST:
    assert((revents & POLLOUT) == POLLOUT);
    if ((revents & (POLLERR | POLLHUP)) != 0)
    {
      fprintf(stderr, "async send fd error. revents=%#hx\n", revents);

      len = sizeof(val);
      ret = getsockopt(connection_ptr->socket, SOL_SOCKET, SO_ERROR, &val, &len);
      if (ret == -1)
      {
        fprintf(stderr, "getsockopt() failed to get socket send error. %d (%s)\n", errno, strerror(errno));
      }
      else
      {
        fprintf(stderr, "async send() error %d (%s)\n", val, strerror(val));
      }
      goto error;
    }
    goto send_request_continue;
  case STATE_READING_REPLY_HEADER:
    assert((revents & POLLIN) == POLLIN);
    if ((revents & (POLLERR | POLLHUP)) != 0)
    {
      fprintf(stderr, "async reply header recv fd error. revents=%#hx\n", revents);

      len = sizeof(val);
      ret = getsockopt(connection_ptr->socket, SOL_SOCKET, SO_ERROR, &val, &len);
      if (ret == -1)
      {
        fprintf(stderr, "getsockopt() failed to get socket recv error. %d (%s)\n", errno, strerror(errno));
      }
      else
      {
        fprintf(stderr, "async recv() error %d (%s)\n", val, strerror(val));
      }
      goto error;
    }
    goto read_reply_header;
  case STATE_READING_REPLY_BODY:
    assert((revents & POLLIN) == POLLIN);
    if ((revents & (POLLERR | POLLHUP)) != 0)
    {
      fprintf(stderr, "async reply body recv fd error. revents=%#hx\n", revents);

      len = sizeof(val);
      ret = getsockopt(connection_ptr->socket, SOL_SOCKET, SO_ERROR, &val, &len);
      if (ret == -1)
      {
        fprintf(stderr, "getsockopt() failed to get socket recv error. %d (%s)\n", errno, strerror(errno));
      }
      else
      {
        fprintf(stderr, "async recv() error %d (%s)\n", val, strerror(val));
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
    fprintf(stderr, "socket() failed. %d (%s)\n", errno, strerror(errno));
    goto error;
  }

  ret = fcntl(connection_ptr->socket, F_SETFL, O_NONBLOCK);
  if (ret == -1)
  {
    fprintf(stderr, "fcntl() failed to set socket non-blocking mode. %d (%s)\n", errno, strerror(errno));
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

    fprintf(stderr, "connect() failed. %d (%s)\n", errno, strerror(errno));
    goto error;
  }

  printf("connect complete.\n");
  goto send_request;

async_connect_done:
  if ((revents & (POLLERR | POLLHUP)) != 0)
  {
    fprintf(stderr, "async connect failed. revents=%#hx\n", revents);
  }

  len = sizeof(val);
  ret = getsockopt(connection_ptr->socket, SOL_SOCKET, SO_ERROR, &val, &len);
  if (ret == -1)
  {
    fprintf(stderr, "getsockopt() failed to get socket connect error. %d (%s)\n", errno, strerror(errno));
    goto error;
  }
  if (val != 0)
  {
    fprintf(stderr, "async connect() failed. %d (%s)\n", val, strerror(val));
    goto error;
  }

  printf("async connect complete.\n");

send_request:
  printf("sending request...\n");

  ret = snprintf(
    connection_ptr->buffer,
    sizeof(connection_ptr->buffer),
    "GET /speedtest/random4000x4000.jpg HTTP/1.1\r\n"
    "User-Agent: netspeed/0.0\r\n"
    "Accept: */*\r\n"
    "Host: %s\r\n"
    "\r\n",
    connection_ptr->host);
  if (ret < -1 || ret >= (int)sizeof(connection_ptr->buffer))
  {
    fprintf(stderr, "snprintf() failed compose request. %d\n", ret);
    goto error;
  }

  connection_ptr->state = STATE_SENDING_REQUEST;
  connection_ptr->offset = 0;
  connection_ptr->size = (size_t)ret;

send_request_continue:
  while (connection_ptr->size > 0)
  {
    sret = send(
      connection_ptr->socket,
      connection_ptr->buffer + connection_ptr->offset,
      connection_ptr->size,
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

      fprintf(stderr, "send() failed. %d (%s)\n", errno, strerror(errno));
      goto error;
    }

    connection_ptr->offset += sret;
    connection_ptr->size -= sret;
  }

  printf("request sent\n");

  connection_ptr->state = STATE_READING_REPLY_HEADER;
  connection_ptr->offset = 0;   /* parsed size */
  connection_ptr->size = 0;     /* read size */

read_reply_header:
  if (connection_ptr->size >= sizeof(connection_ptr->buffer))
  {
    fprintf(stderr, "HTTP reply header too big\n");
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

    fprintf(stderr, "recv() failed. %d (%s)\n", errno, strerror(errno));
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
      printf("header size is %zu bytes\n", connection_ptr->offset);
      for (i = 0; i < connection_ptr->offset; i++)
      {
        if (connection_ptr->buffer[i] < 0)
        {
          fprintf(stderr, "invalid char in HTTP reply header\n");
          goto error;
        }

        connection_ptr->buffer[i] = tolower(connection_ptr->buffer[i]);
      }

      connection_ptr->buffer[connection_ptr->offset] = 0;
      //printf("Header:\n%s\n", connection_ptr->buffer);

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
        printf("total body size is %d bytes\n", val);

        if ((size_t)val < i)
        {
          fprintf(stderr, "body bigger than announced\n");
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
        printf("unknown body size\n");
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

      fprintf(stderr, "recv() failed. %d (%s)\n", errno, strerror(errno));
      goto error;
    }

    connection_ptr->size -= sret;
    connection_ptr->offset += sret;
    //printf("(%zd)", sret); fflush(stdout);
  }

  printf("%zu body bytes read\n", connection_ptr->offset);
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
    printf("closing socket...\n");
    close(connection_ptr->socket);
  }
}

#undef connection_ptr

bool
create_worker(
  const char * type,
  const char * hostname,
  void ** ctx,
  work_fn * work,
  cleanup_fn * cleanup)
{
  struct connection * connection_ptr;
  struct hostent * he_ptr;

  if (strcmp(type, "d") == 0)
  {
  }
  else if (strcmp(type, "u") == 0)
  {
    fprintf(stderr, "upload test not implemented yet.\n");
    return false;
  }
  else
  {
    fprintf(stderr, "unknown type \"%s\".\n", type);
    return false;
  }

  he_ptr = gethostbyname(hostname);
  if (he_ptr == NULL)
  {
    fprintf(stderr, "Cannot resolve \"%s\". h_errno is %d\n", hostname, h_errno);
    return false;
  }

  printf("connecting to %s\n", hostname);

  connection_ptr = malloc(sizeof(struct connection));
  if (connection_ptr == NULL)
  {
    fprintf(stderr, "memory allocation failed.\n");
    return false;
  }

  connection_ptr->host = hostname;
  connection_ptr->state = STATE_NOT_CONNECTED;
  connection_ptr->socket = -1;
  connection_ptr->ip = *(uint32_t *)(he_ptr->h_addr);

  *ctx = connection_ptr;
  *work = worker;
  *cleanup = connection_cleanup;

  return true;
}

int main(int argc, char ** argv)
{
  int ret;
  void * ctx;
  work_fn work;
  cleanup_fn cleanup;
  struct pollfd pollfd;

  printf("Generate network traffic. Written by Nedko Arnaudov.\n");

  if (argc < 2)
  {
    printf("Usage: netspeed <type> <host>\n");
    printf("<type> is either 'u' (upload) or 'd' (download)\n");
    printf("<host> is a ookla speedtest host\n");
    return 0;
  }

  ret = mlockall(MCL_FUTURE);
  if (ret == -1)
  {
    fprintf(stderr, "mlockall() failed. %d (%s)\n", errno, strerror(errno));
    return 1;
  }

  if (!create_worker(argv[1], argv[2], &ctx, &work, &cleanup))
  {
    return 1;
  }

  pollfd.revents = 0;

loop:
  ret = work(ctx, pollfd.revents, &pollfd.fd, &pollfd.events);
  if (ret <= 0)
  {
    ret = -ret;
    goto exit;
  }

  ret = poll(&pollfd, 1, -1);
  if (ret == -1)
  {
    fprintf(stderr, "poll() failed. %d (%s)\n", errno, strerror(errno));
    ret = 1;
    goto exit;
  }

  goto loop;

exit:
  cleanup(ctx);
  return ret;
}
