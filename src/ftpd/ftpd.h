/**
 * File:   ftpd.h
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

#ifndef TK_FTPD_H
#define TK_FTPD_H

#include "tkc/iostream.h"
#include "tkc/event_source_manager.h"

BEGIN_C_DECLS

/**
 * @class ftpd_t
 * @annotation ["fake"]
 * ftp服务器
 *
 */
typedef struct _ftpd_t {
  /**
   * @property {int} port
   * 默认端口。
   */
  uint32_t port;

  /**
   * @property {int} data_port
   * 数据传输的socket。
   */
  uint32_t data_port;

  /**
   * @property {int} sock
   * 监听的socket。
   */
  int sock;

  /**
   * @property {int} data_sock
   * 监听的 data socket。
   */
  int data_sock;

  /**
   * @property {tk_iostream_t*} ios
   * 客户端命令流。
   */
  tk_iostream_t* ios;

  /**
   * @property {tk_iostream_t*} data_ios
   * 客户端数据流。
   */
  tk_iostream_t* data_ios;

  /**
   * @property {char*} root
   * 根目录。
  */
  char* root;

  /**
   * @property {char*} user
   * 用户名。
   */
  char* user;

  /**
   * @property {char*} password
   * 密码。
   */
  char* password;

  /*private*/
  int32_t state;
  event_source_t* source;
  char cwd[MAX_PATH + 1];
  event_source_manager_t* esm;
  char* from_name;
} ftpd_t;

/**
 * @method ftpd_create
 * 创建ftp服务器。
 * @param {event_source_manager_t*} esm 事件管理器。
 * @param {const char*} root 根目录。
 * @param {uint32_t} port 监听的端口。
 * @param {uint32_t} data_port 监听的数据端口。
 * 
 * @return {ftpd_t*} 返回ftp服务器对象。
 */
ftpd_t* ftpd_create(event_source_manager_t* esm, const char* root, uint32_t port,
                    uint32_t data_port);

/**
 * @method ftpd_set_user
 * 设置用户名和密码。
 * @param {ftpd_t*} ftpd ftp服务器对象。
 * @param {const char*} user 用户名。
 * @param {const char*} password 密码。
 * 
 * @return {ret_t} 返回RET_OK表示成功，否则表示失败。
 */
ret_t ftpd_set_user(ftpd_t* ftpd, const char* user, const char* password);

/**
 * @method ftpd_start
 * 启动ftp服务器。
 * @param {ftpd_t*} ftpd ftp服务器对象。
 * 
 * @return {ret_t} 返回RET_OK表示成功，否则表示失败。
 */
ret_t ftpd_start(ftpd_t* ftpd);

/**
 * @method ftpd_destroy
 * 销毁ftp服务器。
 * @param {ftpd_t*} ftpd ftp服务器对象。
 * 
 * @return {ret_t} 返回RET_OK表示成功，否则表示失败。
 */
ret_t ftpd_destroy(ftpd_t* ftpd);

END_C_DECLS

#endif /*TK_FTPD_H*/
