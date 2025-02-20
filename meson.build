project('thuscnet', 'cpp',
  version : '1.0',
  default_options : ['warning_level=3', 'cpp_std=c++20'])

thuscnet_inc = include_directories('include')

executable('thuscnet',
           'src/pcap.cpp',
           'src/main.cpp',
           include_directories : [ thuscnet_inc ],
           install : true)
