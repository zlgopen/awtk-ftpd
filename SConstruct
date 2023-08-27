import os
import scripts.app_helper as app

helper = app.Helper(ARGUMENTS);
helper.set_dll_def('src/ftpd.def').set_libs(['ftpd']).call(DefaultEnvironment)

SConscriptFiles = ['src/SConscript', 'demos/SConscript']
helper.SConscript(SConscriptFiles)
