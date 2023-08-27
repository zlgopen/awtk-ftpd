#ifdef WIN32
#pragma comment(lib, "ws2_32")
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

uint64_t socket_get_client_ip(int sockfd) {
  struct sockaddr_in addr;
  socklen_t addrLen = sizeof(addr);

  if (getpeername(sockfd, (struct sockaddr*)&addr, &addrLen) == 0) {
    return addr.sin_addr.s_addr;
  }

  return 0;
}

uint64_t socket_get_self_ip(int sockfd) {
  struct sockaddr_in addr;
  socklen_t addrLen = sizeof(addr);

  if (getsockname(sockfd, (struct sockaddr*)&addr, &addrLen) == 0) {
    return addr.sin_addr.s_addr;
  }

  return 0;
}

const char* socket_get_client_ip_str(int sockfd, char* ip, int len) {
  struct sockaddr_in addr;
  socklen_t addrLen = sizeof(addr);
  return_value_if_fail(ip != NULL && len > 0, NULL);

  if (getpeername(sockfd, (struct sockaddr*)&addr, &addrLen) == 0) {
    return inet_ntop(AF_INET, &(addr.sin_addr), ip, len);
  }

  return NULL;
}

const char* socket_get_self_ip_str(int sockfd, char* ip, int len) {
  struct sockaddr_in addr;
  socklen_t addrLen = sizeof(addr);
  return_value_if_fail(ip != NULL && len > 0, NULL);

  if (getsockname(sockfd, (struct sockaddr*)&addr, &addrLen) == 0) {
    return inet_ntop(AF_INET, &(addr.sin_addr), ip, len);
  }

  return NULL;
}

ret_t tk_ostream_write_str(tk_ostream_t* out, const char* str) {
  int32_t len = tk_strlen(str);

  log_debug("%p: %s", out, str);
  return tk_ostream_write(out, str, len) == len ? RET_OK : RET_IO;
}

ret_t tk_ostream_printf(tk_ostream_t* out, const char* format, ...) {
  va_list va;
  char buff[1024] = {0};
  va_start(va, format);
  tk_vsnprintf(buff, sizeof(buff) - 1, format, va);
  va_end(va);

  return tk_ostream_write_str(out, buff);
}

static ret_t path_abs_normalize(const char* filename, char* result, int32_t size) {
  char path[MAX_PATH + 1];
  return_value_if_fail(filename != NULL && result != NULL && size > 0, RET_BAD_PARAMS);

  path_abs(filename, path, MAX_PATH);
  return path_normalize(path, result, size);
}

const char* path_normalize_with_root(const char* root, const char* rel_filename,
                                     char filename[MAX_PATH + 1]) {
  char path[MAX_PATH + 1];
  char abs_root[MAX_PATH + 1];
  return_value_if_fail(root != NULL && rel_filename != NULL, NULL);

  path_abs_normalize(root, abs_root, MAX_PATH);

  path_build(path, MAX_PATH, abs_root, rel_filename, NULL);
  path_normalize(path, filename, MAX_PATH);

  if (strncmp(filename, abs_root, strlen(abs_root)) == 0) {
    return filename;
  } else {
    return NULL;
  }
}

ret_t tk_str_replace_char(char* str, char c, char new_c) {
  char* p = str;
  return_value_if_fail(str != NULL, RET_BAD_PARAMS);

  while (*p) {
    if (*p == c) {
      *p = new_c;
    }
    p++;
  }

  return RET_OK;
}
