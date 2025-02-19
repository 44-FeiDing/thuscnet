project('thuscnet', 'cpp',
  version : '0.1',
  default_options : ['warning_level=3', 'cpp_std=c++20'])

add_global_arguments('-D_GLIBCXX_DEBUG', language: 'cpp')

thuscnet_inc = include_directories('include')

executable('thuscnet',
           'src/pcap.cpp',
           'src/main.cpp',
           include_directories : [ thuscnet_inc ],
           install : true)
