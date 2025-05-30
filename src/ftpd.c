/**
 * File:   ftpd.c
 * Author: AWTK Develop Team
 * Brief:  ftp server
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

#include "ftpd.h"

#define FTPD_WELCOME_MSG "220 AWTK FTPD ready.\r\n"

enum _ftpd_state_t {
  FTPD_STATE_NONE = 0,
  FTPD_STATE_USER,
  FTPD_STATE_PASSWORD,
  FTPD_STATE_LOGIN,
};

static bool_t is_from_same_ip(ftpd_t* ftpd) {
  if (ftpd->data_ios != NULL && ftpd->ios != NULL) {
    int fd = tk_object_get_prop_int(TK_OBJECT(ftpd->ios), TK_STREAM_PROP_FD, -1);
    int data_fd = tk_object_get_prop_int(TK_OBJECT(ftpd->data_ios), TK_STREAM_PROP_FD, -1);

    return tk_socket_get_client_ip(fd) == tk_socket_get_client_ip(data_fd);
  }

  return FALSE;
}

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

ret_t ftpd_set_check_user(ftpd_t* ftpd, ftpd_check_user_t check_user, void* ctx) {
  return_value_if_fail(ftpd != NULL, RET_BAD_PARAMS);
  return_value_if_fail(check_user != NULL, RET_BAD_PARAMS);

  ftpd->check_user = check_user;
  ftpd->check_user_ctx = ctx;

  return RET_OK;
}

static const char* ftpd_normalize_filename(ftpd_t* ftpd, const char* path,
                                           char filename[MAX_PATH + 1]) {
  char rel_filename[MAX_PATH + 1] = {0};

  if (*path == '/' || *path == '\\') {
    path_normalize(path, rel_filename, sizeof(rel_filename) - 1);
  } else {
    path_build(filename, MAX_PATH, ftpd->cwd, path, NULL);
    path_normalize(filename, rel_filename, sizeof(rel_filename) - 1);
  }

  return path_abs_normalize_with_root(ftpd->root, rel_filename, filename);
}

static ret_t ftpd_write_550_failed_to_remove_file(tk_ostream_t* out) {
  return tk_ostream_write_str(out, "Failed to remove file.\r\n");
}

static ret_t ftpd_write_550_file_not_exist(tk_ostream_t* out) {
  return tk_ostream_write_str(out, "550 File not exist.\r\n");
}

static ret_t ftpd_write_501_need_an_argv(tk_ostream_t* out) {
  return tk_ostream_write_str(out, "501 Syntax error: command needs an argument.\r\n");
}

static ret_t ftpd_write_501_syntax_error(tk_ostream_t* out) {
  return tk_ostream_printf(out, "501 Syntax error in parameters or arguments.\r\n");
}

static ret_t ftpd_write_550_access_failed(tk_ostream_t* out) {
  return tk_ostream_printf(out, "550 File not found or access denied\r\n");
}

static ret_t ftpd_write_503_need_login(tk_ostream_t* out) {
  return tk_ostream_write_str(out, "503 Login with USER first.\r\n");
}

static ret_t ftpd_write_257_cwd(tk_ostream_t* out, ftpd_t* ftpd) {
  return tk_ostream_printf(out, "257 \"/%s\" is current directory.\r\n", ftpd->cwd);
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
    TKMEM_FREE(ftpd->login_user);
    ftpd->login_user = tk_strdup(user);

    ftpd->state = FTPD_STATE_USER;
    ret = tk_ostream_printf(out, "331 Password required for %s.\r\n", user);
  }

  return ret;
}

static bool_t ftpd_check_user(ftpd_t* ftpd, const char* user, const char* password) {
  if (ftpd->check_user != NULL) {
    return ftpd->check_user(ftpd->check_user_ctx, user, password) == RET_OK;
  } else {
    return tk_str_eq(user, ftpd->user) && tk_str_eq(password, ftpd->password);
  }
}

static ret_t ftpd_cmd_pass(ftpd_t* ftpd, const char* cmd, tk_ostream_t* out) {
  ret_t ret = RET_IO;

  if (ftpd->state != FTPD_STATE_USER) {
    ret = ftpd_write_503_need_login(out);
  } else {
    const char* password = ftpd_get_cmd_arg(ftpd, cmd, out);
    if (password != NULL) {
      if (ftpd_check_user(ftpd, ftpd->login_user, password)) {
        ftpd->state = FTPD_STATE_LOGIN;
        ret = tk_ostream_printf(out, "230 User %s logged in.\r\n", ftpd->login_user);
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

    if (ftpd_normalize_filename(ftpd, path, cwd) == NULL) {
      tk_strncpy(cwd, ftpd->root, sizeof(cwd) - 1);
    }

    ret = fs_change_dir(os_fs(), cwd);
    if (ret != RET_OK) {
      ret = tk_ostream_write_str(out, "550 Failed to change directory.\r\n");
    } else {
      uint32_t len = strlen(ftpd->root);
      tk_strncpy(ftpd->cwd, cwd + len, sizeof(ftpd->cwd) - 1);
      ret = ftpd_write_257_cwd(out, ftpd);
    }
  } else {
    ret = ftpd_write_501_need_an_argv(out);
  }

  return ret;
}

static ret_t ftpd_cmd_sha256(ftpd_t* ftpd, const char* cmd, tk_ostream_t* out) {
  str_t sha256;
  ret_t ret = RET_FAIL;
  const char* path = ftpd_get_cmd_arg(ftpd, cmd, out);

  str_init(&sha256, 256);
  if (path != NULL) {
    char filename[MAX_PATH + 1] = {0};
    if (ftpd_normalize_filename(ftpd, path, filename) != NULL) {
      ret = tk_sha256_file(filename, 10240, &sha256);
    }
  }

  if (ret == RET_OK && sha256.size > 0) {
    ret = tk_ostream_printf(out, "213 %s\r\n", sha256.str);
  } else {
    ret = ftpd_write_501_need_an_argv(out);
  }
  str_reset(&sha256);

  return ret;
}

static ret_t ftpd_cmd_xstat(ftpd_t* ftpd, const char* cmd, tk_ostream_t* out) {
  ret_t ret = RET_OK;
  const char* path = ftpd_get_cmd_arg(ftpd, cmd, out);

  if (path != NULL) {
    char filename[MAX_PATH + 1] = {0};
    if (ftpd_normalize_filename(ftpd, path, filename) != NULL) {
      fs_stat_info_t info;
      if(fs_stat(os_fs(), filename, &info) == RET_OK) {
        str_t result;
        str_init(&result, 1024);
        str_append(&result, "200 ");
        str_append_int64(&result, info.size);
        str_append(&result, " ");
        str_append_int64(&result, info.mtime);
        str_append(&result, " ");
        str_append_int64(&result, info.ctime);
        str_append(&result, " ");
        str_append_int64(&result, info.atime);
        str_append(&result, " ");
        str_append_int(&result, info.is_dir);
        str_append(&result, " ");
        str_append_int(&result, info.is_link);
        str_append(&result, " ");
        str_append_int(&result, info.is_reg_file);
        str_append(&result, " ");
        str_append_int(&result, info.uid);
        str_append(&result, " ");
        str_append_int(&result, info.gid);
        str_append(&result, "\r\n");
        ret = tk_ostream_write(out, result.str, result.size);
        str_reset(&result);

        return ret;
      } else {
        return ftpd_write_550_file_not_exist(out);
      }
    }
  }
  ret = ftpd_write_501_need_an_argv(out);

  return ret;
}

static ret_t ftpd_cmd_size(ftpd_t* ftpd, const char* cmd, tk_ostream_t* out) {
  ret_t ret = RET_OK;
  const char* path = ftpd_get_cmd_arg(ftpd, cmd, out);

  if (path != NULL) {
    uint32_t size = 0;
    char filename[MAX_PATH + 1] = {0};

    if (ftpd_normalize_filename(ftpd, path, filename) != NULL) {
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

  tk_socket_get_self_ip_str(sock, ip, sizeof(ip));
  tk_replace_char(ip, '.', ',');
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

    sock = tk_tcp_connect(ip.str, port);
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

static ret_t mlsd_from_fs_stat_info(str_t* result, fs_stat_info_t* info, const char* name) {
  char modify[32] = {0};
  char perm[32] = {0};
  char unique[32] = {0};
  const char* type = NULL;
  date_time_t* dt = date_time_create();

  if (info->is_dir) {
    if (tk_str_eq(name, ".")) {
      type = "cdir";
    } else if (tk_str_eq(name, "..")) {
      type = "pdir";
    } else {
      type = "dir";
    }
    strcpy(perm, "el");
  } else {
    type = "file";
    strcpy(perm, "r");
  }

  date_time_from_time(dt, info->mtime);
  tk_snprintf(modify, sizeof(modify), "%04d%02d%02d%02d%02d%02d", dt->year, dt->month, dt->day,
              dt->hour, dt->minute, dt->second);
  date_time_destroy(dt);

  tk_snprintf(unique, sizeof(unique), "%xg%x", info->dev, info->ino);
  str_append_format(result, 1024, "modify=%s;perm=%s;size=%u;type=%s;unique=%s; %s\r\n", modify,
                    perm, (uint32_t)info->size, type, unique, name);

  return RET_OK;
}

static ret_t list_from_fs_stat_info(str_t* result, fs_stat_info_t* info, const char* name) {
  char perm[32] = {0};
  char modify[32] = {0};
  date_time_t* dt = date_time_create();

  if (info->is_dir) {
    strcpy(perm, "drwxr-xr-x");
  } else {
    strcpy(perm, "-rw-r--r--");
  }

  date_time_from_time(dt, info->mtime);
  tk_snprintf(modify, sizeof(modify), "%s %d %d:%d", date_time_get_month_name(dt->month), dt->day,
              dt->hour, dt->minute);
  date_time_destroy(dt);

  str_append_format(result, 1024, "%s %d user group %d %s %s\r\n", perm, info->nlink,
                    (uint32_t)info->size, modify, name);

  return RET_OK;
}

static ret_t ftpd_get_list_result(ftpd_t* ftpd, bool_t mlsd, str_t* result) {
  fs_dir_t* dir = NULL;
  char cwd[MAX_PATH + 1] = {0};
  path_build(cwd, sizeof(cwd) - 1, ftpd->root, ftpd->cwd, NULL);

  dir = fs_open_dir(os_fs(), cwd);
  if (dir != NULL) {
    fs_item_t item;
    fs_stat_info_t info;
    while (fs_dir_read(dir, &item) == RET_OK) {
      fs_stat(os_fs(), item.name, &info);
      if (mlsd) {
        mlsd_from_fs_stat_info(result, &info, item.name);
      } else {
        list_from_fs_stat_info(result, &info, item.name);
      }
    }
    fs_dir_close(dir);
  }

  return RET_OK;
}

static ret_t ftpd_cmd_list(ftpd_t* ftpd, const char* cmd, tk_ostream_t* out) {
  char cwd[MAX_PATH + 1] = {0};
  fs_get_cwd(os_fs(), cwd);
  if (is_from_same_ip(ftpd)) {
    str_t result;
    tk_ostream_t* data_out = tk_iostream_get_ostream(ftpd->data_ios);

    tk_ostream_printf(out, "150 File status okay. About to open data connection\r\n");

    str_init(&result, 1000);
    if (strncasecmp(cmd, "MLSD", 4) == 0) {
      ftpd_get_list_result(ftpd, TRUE, &result);
    } else {
      ftpd_get_list_result(ftpd, FALSE, &result);
    }
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
    if (is_from_same_ip(ftpd)) {
      char filename[MAX_PATH + 1] = {0};
      tk_ostream_t* data_out = tk_iostream_get_ostream(ftpd->data_ios);

      if (ftpd_normalize_filename(ftpd, path, filename) != NULL) {
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
          fs_file_close(file);
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
    if (is_from_same_ip(ftpd)) {
      char filename[MAX_PATH + 1] = {0};
      tk_istream_t* data_in = tk_iostream_get_istream(ftpd->data_ios);

      if (ftpd_normalize_filename(ftpd, path, filename) != NULL) {
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

static ret_t ftpd_cmd_dele(ftpd_t* ftpd, const char* cmd, tk_ostream_t* out) {
  ret_t ret = RET_OK;
  const char* path = ftpd_get_cmd_arg(ftpd, cmd, out);

  if (path != NULL) {
    char filename[MAX_PATH + 1] = {0};

    if (ftpd_normalize_filename(ftpd, path, filename) == NULL) {
      return ftpd_write_501_syntax_error(out);
    }

    if (!file_exist(filename)) {
      return ftpd_write_550_file_not_exist(out);
    }

    ret = fs_remove_file(os_fs(), filename);
    if (ret != RET_OK) {
      ret = ftpd_write_550_failed_to_remove_file(out);
    } else {
      ret = tk_ostream_write_str(out, "200 Remove file ok.\r\n");
    }
  } else {
    ret = ftpd_write_501_need_an_argv(out);
  }

  return ret;
}

static ret_t ftpd_cmd_rmd(ftpd_t* ftpd, const char* cmd, tk_ostream_t* out) {
  ret_t ret = RET_OK;
  const char* path = ftpd_get_cmd_arg(ftpd, cmd, out);

  if (path != NULL) {
    char full_path[MAX_PATH + 1] = {0};

    if (ftpd_normalize_filename(ftpd, path, full_path) == NULL) {
      return ftpd_write_501_syntax_error(out);
    }

    if (!dir_exist(full_path)) {
      return tk_ostream_write_str(out, "550 Directory not exist.\r\n");
    }

    ret = fs_remove_dir_r(os_fs(), full_path);
    if (ret != RET_OK) {
      ret = tk_ostream_write_str(out, "550 Failed to remove directory.\r\n");
    } else {
      ret = tk_ostream_write_str(out, "200 Remove directory ok.\r\n");
    }
  } else {
    ret = ftpd_write_501_need_an_argv(out);
  }

  return ret;
}

static ret_t ftpd_cmd_mkd(ftpd_t* ftpd, const char* cmd, tk_ostream_t* out) {
  ret_t ret = RET_OK;
  const char* path = ftpd_get_cmd_arg(ftpd, cmd, out);

  if (path != NULL) {
    char full_path[MAX_PATH + 1] = {0};

    if (ftpd_normalize_filename(ftpd, path, full_path) == NULL) {
      return ftpd_write_501_syntax_error(out);
    }

    if (dir_exist(full_path)) {
      return tk_ostream_write_str(out, "550 Directory exist.\r\n");
    }

    ret = fs_create_dir_r(os_fs(), full_path);
    if (ret != RET_OK) {
      ret = tk_ostream_write_str(out, "550 Failed to create directory.\r\n");
    } else {
      ret = tk_ostream_write_str(out, "200 Create directory ok.\r\n");
    }
  } else {
    ret = ftpd_write_501_need_an_argv(out);
  }

  return ret;
}

static ret_t ftpd_cmd_rnfr(ftpd_t* ftpd, const char* cmd, tk_ostream_t* out) {
  ret_t ret = RET_OK;
  const char* path = ftpd_get_cmd_arg(ftpd, cmd, out);

  if (path != NULL) {
    char full_path[MAX_PATH + 1] = {0};

    if (ftpd_normalize_filename(ftpd, path, full_path) == NULL) {
      return ftpd_write_501_syntax_error(out);
    }

    if (!dir_exist(full_path) && !file_exist(full_path)) {
      return tk_ostream_write_str(out, "550 File or directory not exist.\r\n");
    }

    TKMEM_FREE(ftpd->from_name);
    ftpd->from_name = tk_strdup(full_path);
    ret = tk_ostream_write_str(out, "200 OK.\r\n");
  } else {
    ret = ftpd_write_501_need_an_argv(out);
  }

  return ret;
}

static ret_t ftpd_cmd_rnto(ftpd_t* ftpd, const char* cmd, tk_ostream_t* out) {
  ret_t ret = RET_OK;
  const char* path = ftpd_get_cmd_arg(ftpd, cmd, out);

  if (path != NULL) {
    char full_path[MAX_PATH + 1] = {0};

    if (ftpd_normalize_filename(ftpd, path, full_path) == NULL || ftpd->from_name == NULL) {
      return ftpd_write_501_syntax_error(out);
    }

    if (dir_exist(full_path) || file_exist(full_path)) {
      return tk_ostream_write_str(out, "550 File or directory exist.\r\n");
    }

    if (dir_exist(ftpd->from_name)) {
      ret = fs_dir_rename(os_fs(), ftpd->from_name, full_path);
    } else {
      ret = fs_file_rename(os_fs(), ftpd->from_name, full_path);
    }
    TKMEM_FREE(ftpd->from_name);

    log_debug("%s => %s\n", ftpd->from_name, full_path);
    if (ret != RET_OK) {
      ret = tk_ostream_write_str(out, "550 Failed to rename.\r\n");
    } else {
      ret = tk_ostream_write_str(out, "200 Rename ok.\r\n");
    }
  } else {
    ret = ftpd_write_501_need_an_argv(out);
  }

  return ret;
}

static ret_t ftpd_cmd_opts(ftpd_t* ftpd, const char* cmd, tk_ostream_t* out) {
  const char* args = ftpd_get_cmd_arg(ftpd, cmd, out);
  if (args != NULL) {
    if (strncasecmp(args, "UTF8 ON", 7) == 0) {
      tk_ostream_printf(out, "200 Always in UTF8 mode.\r\n");
    } else {
      tk_ostream_printf(out, "500 Command \"%s\" not understood.\r\n", cmd);
    }
  } else {
    return ftpd_write_501_syntax_error(out);
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
  } else if (strncasecmp(cmd, "CWD", 3) == 0) {
    ftpd_cmd_cwd(ftpd, cmd, out);
  } else if (strncasecmp(cmd, "CDUP", 4) == 0) {
    ftpd_cmd_cwd(ftpd, "CWD ..", out);
  } else if (strncasecmp(cmd, "TYPE", 4) == 0) {
    ftpd_cmd_type(ftpd, cmd, out);
  } else if (strncasecmp(cmd, "SIZE", 4) == 0) {
    ftpd_cmd_size(ftpd, cmd, out);
  } else if (strncasecmp(cmd, "XSTAT", 5) == 0) {
    ftpd_cmd_xstat(ftpd, cmd, out);
  } else if (strncasecmp(cmd, "SHA256", 6) == 0) {
    ftpd_cmd_sha256(ftpd, cmd, out);
  } else if (strncasecmp(cmd, "PASV", 4) == 0) {
    ftpd_cmd_pasv(ftpd, cmd, out);
  } else if (strncasecmp(cmd, "PORT", 4) == 0) {
    ftpd_cmd_port(ftpd, cmd, out);
  } else if (strncasecmp(cmd, "LIST", 4) == 0 || strncasecmp(cmd, "NLST", 4) == 0) {
    return ftpd_cmd_list(ftpd, cmd, out);
  } else if (strncasecmp(cmd, "OPTS", 4) == 0) {
    return ftpd_cmd_opts(ftpd, cmd, out);
  } else if (strncasecmp(cmd, "MLSD", 4) == 0) {
    return ftpd_cmd_list(ftpd, cmd, out);
  } else if (strncasecmp(cmd, "RETR", 4) == 0) {
    return ftpd_cmd_retr(ftpd, cmd, out);
  } else if (strncasecmp(cmd, "STOR", 4) == 0) {
    return ftpd_cmd_stor(ftpd, cmd, out);
  } else if (strncasecmp(cmd, "DELE", 4) == 0) {
    return ftpd_cmd_dele(ftpd, cmd, out);
  } else if (strncasecmp(cmd, "MKD", 3) == 0 || strncasecmp(cmd, "XMKD", 4) == 0) {
    return ftpd_cmd_mkd(ftpd, cmd, out);
  } else if (strncasecmp(cmd, "RMD", 3) == 0 || strncasecmp(cmd, "XRMD", 4) == 0) {
    return ftpd_cmd_rmd(ftpd, cmd, out);
  } else if (strncasecmp(cmd, "PWD", 3) == 0 || strncasecmp(cmd, "XPWD", 4) == 0) {
    ftpd_cmd_pwd(ftpd, cmd, out);
  } else if (strncasecmp(cmd, "RNFR", 4) == 0) {
    return ftpd_cmd_rnfr(ftpd, cmd, out);
  } else if (strncasecmp(cmd, "RNTO", 4) == 0) {
    return ftpd_cmd_rnto(ftpd, cmd, out);
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
  int sock = tk_tcp_accept(fd);

  if (sock >= 0) {
    tk_iostream_t* ios = tk_iostream_tcp_create(sock);

    log_debug("client connected:%d\n", sock);
    if (ios != NULL) {
      TK_OBJECT_UNREF(ftpd->data_ios);
      ftpd->data_ios = ios;
    } else {
      log_debug("oom! disconnected:%d\n", sock);
      tk_socket_close(sock);
    }
  } else {
    log_debug("error disconnected:%d\n", sock);
    tk_socket_close(sock);
  }

  return RET_OK;
}

static ret_t ftpd_on_client(event_source_t* source) {
  event_source_fd_t* event_source_fd = (event_source_fd_t*)source;
  ftpd_t* ftpd = (ftpd_t*)(event_source_fd->ctx);
  int fd = event_source_get_fd(source);
  int sock = tk_tcp_accept(fd);

  if (ftpd->ios != NULL) {
    const char* msg = "530 server busy.\r\n";
    tk_socket_send(sock, msg, strlen(msg), 0);
    tk_socket_close(sock);
    log_debug("close %d: %s", sock, msg);
    return RET_OK;
  }

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
      TK_OBJECT_UNREF(client_source);
      tk_ostream_write_str(out, FTPD_WELCOME_MSG);
    } else {
      log_debug("oom! disconnected:%d\n", sock);
      tk_socket_close(sock);
    }
  } else {
    log_debug("error disconnected:%d\n", sock);
    tk_socket_close(sock);
  }
  return RET_OK;
}

static ret_t ftpd_listen(ftpd_t* ftpd) {
  int sock = -1;
  event_source_t* source = NULL;
  return_value_if_fail(ftpd != NULL, RET_BAD_PARAMS);

  sock = tk_tcp_listen(ftpd->port);
  return_value_if_fail(sock >= 0, RET_BAD_PARAMS);

  ftpd->sock = sock;
  source = event_source_fd_create(sock, ftpd_on_client, ftpd);
  return_value_if_fail(source != NULL, RET_OOM);

  log_debug("ftpd listen on %d\n", ftpd->port);
  event_source_manager_add(ftpd->esm, source);
  TK_OBJECT_UNREF(source);

  return RET_OK;
}

static ret_t ftpd_listen_data_port(ftpd_t* ftpd) {
  int sock = -1;
  event_source_t* source = NULL;
  return_value_if_fail(ftpd != NULL, RET_BAD_PARAMS);

  sock = tk_tcp_listen(ftpd->data_port);
  return_value_if_fail(sock >= 0, RET_BAD_PARAMS);

  ftpd->data_sock = sock;
  source = event_source_fd_create(sock, ftpd_on_data_client, ftpd);
  return_value_if_fail(source != NULL, RET_OOM);

  log_debug("ftpd data listen on %d\n", ftpd->data_port);
  event_source_manager_add(ftpd->esm, source);
  TK_OBJECT_UNREF(source);

  return RET_OK;
}

ret_t ftpd_start(ftpd_t* ftpd) {
  return_value_if_fail(ftpd != NULL && ftpd->sock < 0, RET_BAD_PARAMS);
  return_value_if_fail((ftpd->user != NULL || ftpd->check_user != NULL), RET_BAD_PARAMS);

  fs_change_dir(os_fs(), ftpd->root);

  if (ftpd_listen(ftpd) != RET_OK) {
    return RET_FAIL;
  }

  if (ftpd_listen_data_port(ftpd) != RET_OK) {
    return RET_FAIL;
  }

  return RET_OK;
}

ret_t ftpd_destroy(ftpd_t* ftpd) {
  return_value_if_fail(ftpd != NULL, RET_BAD_PARAMS);

  if (ftpd->sock >= 0) {
    tk_socket_close(ftpd->sock);
    ftpd->sock = -1;
  }
  
  if (ftpd->data_sock >= 0) {
    tk_socket_close(ftpd->data_sock);
    ftpd->data_sock = -1;
  }

  if (ftpd->ios != NULL) {
    TK_OBJECT_UNREF(ftpd->ios);
  }
  
  if (ftpd->data_ios != NULL) {
    TK_OBJECT_UNREF(ftpd->data_ios);
  }

  TKMEM_FREE(ftpd->root);
  TKMEM_FREE(ftpd->user);
  TKMEM_FREE(ftpd->password);
  TKMEM_FREE(ftpd->from_name);

  TKMEM_FREE(ftpd);

  return RET_OK;
}
