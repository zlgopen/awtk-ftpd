#include "awtk.h"
#include "ftpd/ftpd.h"

static ftpd_t* s_ftpd = NULL;

static ret_t on_close_clicked(void* ctx, event_t* e) {
  tk_quit();
  return RET_OK;
}

static ret_t main_window_create(void) {
  widget_t* win = window_open("main");
  widget_child_on(win, "close", EVT_CLICK, on_close_clicked, NULL);

  return RET_OK;
}

ret_t application_init(void) {
  event_source_manager_t* esm = main_loop_get_event_source_manager(main_loop());
  socket_init();
  s_ftpd = ftpd_create(esm, "./", 2121, 2122);
  ftpd_set_user(s_ftpd, "admin", "admin");
  main_window_create();
  return ftpd_start(s_ftpd);
}

ret_t application_exit(void) {
  ftpd_destroy(s_ftpd);
  socket_deinit();
  
  return RET_OK;
}

#include "../res/assets.inc"
#include "awtk_main.inc"
