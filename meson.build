project('pm', 'c', 'cpp')

libpm_sources = files(
'src/extprocess.cpp'
)

libpm_include_dirs = include_directories('src')
libpm_lib = static_library('pm', libpm_sources, include_directories : libpm_include_dirs)
libpm_dep = declare_dependency(include_directories : libpm_include_dirs, link_with : libpm_lib)

subdir('testsrc')


