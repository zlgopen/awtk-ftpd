/**
 * File:   ftpd.c
 * Author: AWTK Develop Team
 * Brief:  map one str to another str
 *
 * Copyright (c) 2018 - 2023  Guangzhou ZHIYUAN Electronics Co.,Ltd.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * License file for more details.
 *
 */

/**
 * History:
 * ================================================================
 * 2023-08-26 Li XianJing <xianjimli@hotmail.com> created
 *
 */

#include "tkc.h"
#include "streams/inet/iostream_tcp.h"

#include "ftpd/ftpd.h"
#include "./helper.inc"

#define FTPD_WELCOME_MSG "220 AWTK FTPD ready.\r\n"

enum _ftpd_state_t {
  FTPD_STATE_NONE = 0,
  FTPD_STATE_USER,
  FTPD_STATE_PASSWORD,
  FTPD_STATE_LOGIN,
};

ftpd_t* ftpd_create(event_source_manager_t* esm, const char* root, uint32_t port,
                    uint32_t data_port) {
  ftpd_t* ftpd = NULL;
  char path[MAX_PATH + 1] = {0};
  return_value_if_fail(esm != NULL, NULL);
  return_value_if_fail(root != NULL, NULL);
  return_value_if_fail(port > 0, NULL);
  return_value_if_fail(path_exist(root), NULL);

  ftpd = TKMEM_ZALLOC(ftpd_t);
  return_value_if_fail(ftpd != NULL, NULL);

  ftpd->esm = esm;
  ftpd->sock = -1;
  ftpd->port = port;
  ftpd->data_port = data_port;
  ftpd->state = FTPD_STATE_NONE;
  path_abs_normalize(root, path, MAX_PATH);
  ftpd->root = tk_strdup(path);
  tk_strncpy(ftpd->cwd, path, sizeof(ftpd->cwd) - 1);

  if (!dir_exist(ftpd->root)) {
    log_debug("%s not exist\n", ftpd->root);
    ftpd_destroy(ftpd);
    ftpd = NULL;
  }

  return ftpd;
}

ret_t ftpd_set_user(ftpd_t* ftpd, const char* user, const char* password) {
  return_value_if_fail(ftpd != NULL, RET_BAD_PARAMS);
  return_value_if_fail(user != NULL, RET_BAD_PARAMS);
  return_value_if_fail(password != NULL, RET_BAD_PARAMS);

  TKMEM_FREE(ftpd->user);
  TKMEM_FREE(ftpd->password);
  ftpd->user = tk_strdup(user);
  ftpd->password = tk_strdup(password);

  return RET_OK;
}

static ret_t ftpd_write_501_need_an_argv(tk_ostream_t* out) {
  return tk_ostream_write_str(out, "501 Syntax error: command needs an argument.\r\n");
}

static ret_t ftpd_write_550_access_failed(tk_ostream_t* out) {
  return tk_ostream_printf(out, "550 File not found or access denied\r\n");
}

static ret_t ftpd_write_530_login_failed(tk_ostream_t* out) {
  return tk_ostream_write_str(out, "530 Login incorrect.\r\n");
}

static ret_t ftpd_write_503_need_login(tk_ostream_t* out) {
  return tk_ostream_write_str(out, "503 Login with USER first.\r\n");
}

static ret_t ftpd_write_257_cwd(tk_ostream_t* out, ftpd_t* ftpd) {
  char* cwd = ftpd->cwd;
  char* root = ftpd->root;
  int32_t len = strlen(root);
  const char* rel_cwd = NULL;

  if (strncmp(cwd, root, len) == 0) {
    rel_cwd = cwd + len - 1;
  } else {
    rel_cwd = "/";
  }

  return tk_ostream_printf(out, "257 \"%s\" is current directory.\r\n", rel_cwd);
}

static const char* ftpd_get_cmd_arg(ftpd_t* ftpd, const char* cmd, tk_ostream_t* out) {
  const char* p = strchr(cmd, ' ');
  if (p != NULL) {
    return p + 1;
  } else {
    ftpd_write_501_need_an_argv(out);
    return NULL;
  }
}

static ret_t ftpd_cmd_user(ftpd_t* ftpd, const char* cmd, tk_ostream_t* out) {
  ret_t ret = RET_FAIL;
  const char* user = ftpd_get_cmd_arg(ftpd, cmd, out);

  if (user != NULL) {
    if (tk_str_eq(user, ftpd->user)) {
      ftpd->state = FTPD_STATE_USER;
      ret = tk_ostream_printf(out, "331 Password required for %s.\r\n", user);
    } else {
      ret = ftpd_write_530_login_failed(out);
    }
  }

  return ret;
}

static ret_t ftpd_cmd_pass(ftpd_t* ftpd, const char* cmd, tk_ostream_t* out) {
  ret_t ret = RET_IO;

  if (ftpd->state != FTPD_STATE_USER) {
    ret = ftpd_write_503_need_login(out);
  } else {
    const char* password = ftpd_get_cmd_arg(ftpd, cmd, out);
    if (password != NULL) {
      if (tk_str_eq(password, ftpd->password)) {
        ftpd->state = FTPD_STATE_LOGIN;
        ret = tk_ostream_printf(out, "230 User %s logged in.\r\n", ftpd->user);
      } else {
        ret = ftpd_write_503_need_login(out);
      }
    }
  }

  return ret;
}

static ret_t ftpd_cmd_syst(ftpd_t* ftpd, const char* cmd, tk_ostream_t* out) {
  return tk_ostream_write_str(out, "215 UNIX Type: AWTK\r\n");
}

static ret_t ftpd_cmd_pwd(ftpd_t* ftpd, const char* cmd, tk_ostream_t* out) {
  return ftpd_write_257_cwd(out, ftpd);
}

static ret_t ftpd_cmd_cwd(ftpd_t* ftpd, const char* cmd, tk_ostream_t* out) {
  ret_t ret = RET_OK;
  const char* path = ftpd_get_cmd_arg(ftpd, cmd, out);

  if (path != NULL) {
    char cwd[MAX_PATH + 1] = {0};
    if (path_normalize_with_root(ftpd->root, path, cwd) == NULL) {
      tk_strncpy(cwd, ftpd->root, sizeof(cwd) - 1);
    }
    ret = fs_change_dir(os_fs(), cwd);

    if (ret != RET_OK) {
      ret = tk_ostream_write_str(out, "550 Failed to change directory.\r\n");
    } else {
      tk_strncpy(ftpd->cwd, cwd, sizeof(ftpd->cwd) - 1);
      ret = ftpd_write_257_cwd(out, ftpd);
    }
  } else {
    ret = ftpd_write_501_need_an_argv(out);
  }

  return ret;
}

static ret_t ftpd_cmd_size(ftpd_t* ftpd, const char* cmd, tk_ostream_t* out) {
  ret_t ret = RET_OK;
  const char* path = ftpd_get_cmd_arg(ftpd, cmd, out);

  if (path != NULL) {
    uint32_t size = 0;
    char filename[MAX_PATH + 1] = {0};

    if (path_normalize_with_root(ftpd->root, path, filename) != NULL) {
      size = file_get_size(filename);
    } else {
      size = 0;
    }
    ret = tk_ostream_printf(out, "213 %u\r\n", size);
  } else {
    ret = ftpd_write_501_need_an_argv(out);
  }

  return ret;
}

static ret_t ftpd_cmd_type(ftpd_t* ftpd, const char* cmd, tk_ostream_t* out) {
  tk_ostream_printf(out, "200 Switching to Binary mode.\r\n");
  return RET_OK;
}

static ret_t ftpd_cmd_pasv(ftpd_t* ftpd, const char* cmd, tk_ostream_t* out) {
  char ip[64] = {0};
  int sock = tk_object_get_prop_int(TK_OBJECT(out), TK_STREAM_PROP_FD, -1);

  socket_get_self_ip_str(sock, ip, sizeof(ip));
  tk_str_replace_char(ip, '.', ',');
  tk_ostream_printf(out, "227 Entering Passive Mode (%s,%d,%d).\r\n", ip, ftpd->data_port / 256,
                    ftpd->data_port % 256);
  return RET_OK;
}

static ret_t ftpd_cmd_port(ftpd_t* ftpd, const char* cmd, tk_ostream_t* out) {
  str_t ip;
  int port = 0;
  tokenizer_t t;
  int sock = -1;
  tk_iostream_t* ios = NULL;
  const char* p = ftpd_get_cmd_arg(ftpd, cmd, out);

  if (p != NULL) {
    tokenizer_init(&t, p, strlen(p), ",");

    str_init(&ip, 32);
    str_append(&ip, tokenizer_next_str(&t));
    str_append(&ip, ".");
    str_append(&ip, tokenizer_next_str(&t));
    str_append(&ip, ".");
    str_append(&ip, tokenizer_next_str(&t));
    str_append(&ip, ".");
    str_append(&ip, tokenizer_next_str(&t));

    port = tokenizer_next_int(&t, 0) << 8;
    port |= tokenizer_next_int(&t, 0);

    log_debug("ip:%s port:%d\n", ip.str, port);

    sock = tcp_connect(ip.str, port);
    ios = tk_iostream_tcp_create(sock);
    if (ios != NULL) {
      tk_ostream_printf(out, "200 PORT command successful.\r\n");
      TK_OBJECT_UNREF(ftpd->data_ios);
      ftpd->data_ios = ios;
    } else {
      tk_ostream_printf(out, "500 PORT command failed.\r\n");
    }

    return RET_OK;
  } else {
    return ftpd_write_501_need_an_argv(out);
  }
}

static ret_t ftpd_get_list_result(ftpd_t* ftpd, str_t* result) {
  fs_dir_t* dir = fs_open_dir(os_fs(), ftpd->cwd);
  if (dir != NULL) {
    fs_item_t item;
    while (fs_dir_read(dir, &item) == RET_OK) {
      if (item.is_dir) {
        /*FIXME:*/
        str_append_format(result, 512, "--drwxr-xr-x   1 staff staff        11 Aug 20 00:23 %s\r\n",
                          item.name);
      } else if (item.is_reg_file) {
        str_append_format(result, 512,
                          "--rwxr-xr-x   1 staff      staff        11 Aug 20 00:23 %s\r\n",
                          item.name);
      }
    }
    fs_dir_close(dir);
  }

  return RET_OK;
}

static ret_t ftpd_cmd_list(ftpd_t* ftpd, const char* cmd, tk_ostream_t* out) {
  char cwd[MAX_PATH + 1] = {0};

  fs_get_cwd(os_fs(), cwd);
  if (ftpd->data_ios != NULL) {
    str_t result;
    tk_ostream_t* data_out = tk_iostream_get_ostream(ftpd->data_ios);

    tk_ostream_printf(out, "150 File status okay. About to open data connection\r\n");

    str_init(&result, 1000);
    ftpd_get_list_result(ftpd, &result);
    tk_ostream_write_str(data_out, result.str);
    str_reset(&result);

    tk_ostream_printf(out, "226 Transfer complete\r\n");
    TK_OBJECT_UNREF(ftpd->data_ios);

    return RET_OK;
  } else {
    ftpd_write_550_access_failed(out);
    return RET_REMOVE;
  }
}

static ret_t ftpd_cmd_retr(ftpd_t* ftpd, const char* cmd, tk_ostream_t* out) {
  const char* path = ftpd_get_cmd_arg(ftpd, cmd, out);

  if (path != NULL) {
    if (ftpd->data_ios != NULL) {
      char filename[MAX_PATH + 1] = {0};
      tk_ostream_t* data_out = tk_iostream_get_ostream(ftpd->data_ios);

      if (path_normalize_with_root(ftpd->root, path, filename) != NULL) {
        fs_file_t* file = fs_open_file(os_fs(), filename, "rb");
        if (file != NULL) {
          int ret = 0;
          char buff[1024] = {0};
          int32_t size = file_get_size(filename);
          tk_ostream_printf(out, "150 Opening BINARY mode data connection for %s(%d bytes).\r\n",
                            path, size);
          do {
            ret = fs_file_read(file, buff, sizeof(buff));
            if (ret <= 0) {
              break;
            }
            ret = tk_ostream_write(data_out, buff, ret);
            if (ret <= 0) {
              break;
            }
          } while (TRUE);
          tk_ostream_printf(out, "226 Transfer complete\r\n");
        } else {
          ftpd_write_550_access_failed(out);
        }
      }

      TK_OBJECT_UNREF(ftpd->data_ios);
      return RET_OK;
    } else {
      ftpd_write_550_access_failed(out);
      return RET_REMOVE;
    }
  } else {
    return ftpd_write_501_need_an_argv(out);
  }
}

static ret_t ftpd_cmd_stor(ftpd_t* ftpd, const char* cmd, tk_ostream_t* out) {
  const char* path = ftpd_get_cmd_arg(ftpd, cmd, out);

  if (path != NULL) {
    if (ftpd->data_ios != NULL) {
      char filename[MAX_PATH + 1] = {0};
      tk_istream_t* data_in = tk_iostream_get_istream(ftpd->data_ios);

      if (path_normalize_with_root(ftpd->root, path, filename) != NULL) {
        int ret = 0;
        char buff[1024] = {0};
        fs_file_t* file = fs_open_file(os_fs(), filename, "wb+");

        if (file != NULL) {
          tk_ostream_printf(out, "150 Ok to send data.\r\n");
          do {
            ret = tk_istream_read(data_in, buff, sizeof(buff));
            if (ret <= 0) {
              break;
            }
            fs_file_write(file, buff, ret);
          } while (TRUE);
          fs_file_close(file);

          tk_ostream_printf(out, "226 Transfer complete\r\n");
        } else {
          ftpd_write_550_access_failed(out);
        }
      } else {
        ftpd_write_550_access_failed(out);
      }
      TK_OBJECT_UNREF(ftpd->data_ios);
      return RET_OK;
    } else {
      ftpd_write_550_access_failed(out);
      return RET_REMOVE;
    }
  } else {
    return ftpd_write_501_need_an_argv(out);
  }

  return RET_OK;
}

static ret_t ftpd_cmd_quit(ftpd_t* ftpd, const char* cmd, tk_ostream_t* out) {
  tk_ostream_printf(out, "221 Goodbye.\r\n");
  return RET_REMOVE;
}

static ret_t ftpd_dispatch(ftpd_t* ftpd, const char* cmd) {
  tk_ostream_t* out = tk_iostream_get_ostream(ftpd->ios);

  if (ftpd->state != FTPD_STATE_LOGIN) {
    if (strncasecmp(cmd, "USER", 4) != 0 && strncasecmp(cmd, "PASS", 4) != 0) {
      return ftpd_write_503_need_login(out);
    }
  }

  log_debug("cmd: %s\n", cmd);
  if (strncasecmp(cmd, "USER", 4) == 0) {
    ftpd_cmd_user(ftpd, cmd, out);
  } else if (strncasecmp(cmd, "PASS", 4) == 0) {
    ftpd_cmd_pass(ftpd, cmd, out);
  } else if (strncasecmp(cmd, "SYST", 4) == 0) {
    ftpd_cmd_syst(ftpd, cmd, out);
  } else if (strncasecmp(cmd, "PWD", 3) == 0) {
    ftpd_cmd_pwd(ftpd, cmd, out);
  } else if (strncasecmp(cmd, "CWD", 3) == 0) {
    ftpd_cmd_cwd(ftpd, cmd, out);
  } else if (strncasecmp(cmd, "TYPE", 4) == 0) {
    ftpd_cmd_type(ftpd, cmd, out);
  } else if (strncasecmp(cmd, "SIZE", 4) == 0) {
    ftpd_cmd_size(ftpd, cmd, out);
  } else if (strncasecmp(cmd, "PASV", 4) == 0) {
    ftpd_cmd_pasv(ftpd, cmd, out);
  } else if (strncasecmp(cmd, "PORT", 4) == 0) {
    ftpd_cmd_port(ftpd, cmd, out);
  } else if (strncasecmp(cmd, "LIST", 4) == 0) {
    return ftpd_cmd_list(ftpd, cmd, out);
  } else if (strncasecmp(cmd, "RETR", 4) == 0) {
    return ftpd_cmd_retr(ftpd, cmd, out);
  } else if (strncasecmp(cmd, "STOR", 4) == 0) {
    return ftpd_cmd_stor(ftpd, cmd, out);
  } else if (strncasecmp(cmd, "QUIT", 4) == 0) {
    return ftpd_cmd_quit(ftpd, cmd, out);
  } else {
    log_debug("unknown cmd:%s\n", cmd);
    tk_ostream_printf(out, "500 Command \"%s\" not understood.\r\n", cmd);
  }
  return RET_NOT_IMPL;
}

static ret_t ftpd_on_cmd(event_source_t* source) {
  int ret = 0;
  char buff[1024] = {0};
  event_source_fd_t* event_source_fd = (event_source_fd_t*)source;
  ftpd_t* ftpd = (ftpd_t*)(event_source_fd->ctx);
  tk_istream_t* in = tk_iostream_get_istream(ftpd->ios);

  ret = tk_istream_read(in, buff, sizeof(buff) - 1);
  log_debug("client data:ret=%d\n", ret);

  if (ret > 0) {
    str_t str;

    buff[ret] = '\0';
    str_attach_with_size(&str, buff, strlen(buff), sizeof(buff));
    str_trim_right(&str, "\r\n");

    return ftpd_dispatch(ftpd, str.str);
  } else {
    TK_OBJECT_UNREF(ftpd->ios);
    return RET_REMOVE;
  }
}

static ret_t ftpd_on_data_client(event_source_t* source) {
  event_source_fd_t* event_source_fd = (event_source_fd_t*)source;
  ftpd_t* ftpd = (ftpd_t*)(event_source_fd->ctx);
  int fd = event_source_get_fd(source);
  int sock = tcp_accept(fd);

  if (sock >= 0) {
    tk_iostream_t* ios = tk_iostream_tcp_create(sock);

    log_debug("client connected:%d\n", sock);
    if (ios != NULL) {
      TK_OBJECT_UNREF(ftpd->data_ios);
      ftpd->data_ios = ios;
    } else {
      log_debug("oom! disconnected:%d\n", sock);
      socket_close(sock);
    }
  } else {
    log_debug("error disconnected:%d\n", sock);
    socket_close(sock);
  }

  return RET_OK;
}

static ret_t ftpd_on_client(event_source_t* source) {
  event_source_fd_t* event_source_fd = (event_source_fd_t*)source;
  ftpd_t* ftpd = (ftpd_t*)(event_source_fd->ctx);
  int fd = event_source_get_fd(source);
  int sock = tcp_accept(fd);

  event_source_manager_remove(ftpd->esm, ftpd->source);
  TK_OBJECT_UNREF(ftpd->ios);

  if (sock >= 0) {
    log_debug("client connected:%d\n", sock);
    tk_iostream_t* ios = tk_iostream_tcp_create(sock);
    if (ios != NULL) {
      tk_ostream_t* out = tk_iostream_get_ostream(ios);
      event_source_t* client_source = event_source_fd_create(sock, ftpd_on_cmd, ftpd);
      event_source_manager_add(ftpd->esm, client_source);
      ftpd->ios = ios;
      ftpd->source = client_source;
      OBJECT_UNREF(client_source);
      tk_ostream_write_str(out, FTPD_WELCOME_MSG);
    } else {
      log_debug("oom! disconnected:%d\n", sock);
      socket_close(sock);
    }
  } else {
    log_debug("error disconnected:%d\n", sock);
    socket_close(sock);
  }
  return RET_OK;
}

static ret_t ftpd_listen(ftpd_t* ftpd) {
  int sock = -1;
  event_source_t* source = NULL;
  return_value_if_fail(ftpd != NULL, RET_BAD_PARAMS);

  sock = tcp_listen(ftpd->port);
  return_value_if_fail(sock >= 0, RET_BAD_PARAMS);

  ftpd->sock = sock;
  source = event_source_fd_create(sock, ftpd_on_client, ftpd);
  return_value_if_fail(source != NULL, RET_OOM);

  log_debug("listen on %d\n", ftpd->port);
  event_source_manager_add(ftpd->esm, source);
  OBJECT_UNREF(source);

  return RET_OK;
}

static ret_t ftpd_listen_data_port(ftpd_t* ftpd) {
  int sock = -1;
  event_source_t* source = NULL;
  return_value_if_fail(ftpd != NULL, RET_BAD_PARAMS);

  sock = tcp_listen(ftpd->data_port);
  return_value_if_fail(sock >= 0, RET_BAD_PARAMS);

  ftpd->data_sock = sock;
  source = event_source_fd_create(sock, ftpd_on_data_client, ftpd);
  return_value_if_fail(source != NULL, RET_OOM);

  log_debug("listen on %d\n", ftpd->data_port);
  event_source_manager_add(ftpd->esm, source);
  OBJECT_UNREF(source);

  return RET_OK;
}

ret_t ftpd_start(ftpd_t* ftpd) {
  return_value_if_fail(ftpd != NULL && ftpd->sock < 0, RET_BAD_PARAMS);
  return_value_if_fail(ftpd->user != NULL, RET_BAD_PARAMS);
  return_value_if_fail(ftpd->password != NULL, RET_BAD_PARAMS);

  fs_change_dir(os_fs(), ftpd->root);

  ftpd_listen(ftpd);
  ftpd_listen_data_port(ftpd);

  return RET_OK;
}

ret_t ftpd_destroy(ftpd_t* ftpd) {
  return_value_if_fail(ftpd != NULL, RET_BAD_PARAMS);

  if (ftpd->sock >= 0) {
    socket_close(ftpd->sock);
    ftpd->sock = -1;
  }

  if (ftpd->ios != NULL) {
    TK_OBJECT_UNREF(ftpd->ios);
  }

  TKMEM_FREE(ftpd->root);
  TKMEM_FREE(ftpd->user);
  TKMEM_FREE(ftpd->password);

  TKMEM_FREE(ftpd);

  return RET_OK;
}