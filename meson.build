project('thuscnet', 'cpp',
  version : '4.0', default_options: ['cpp_std=c++20'])

thuscnet_inc = include_directories('include')

executable('thuscnet',
           'src/utilities.cpp',
           'src/pcap.cpp',
           'src/ethernet.cpp',
           'src/ip.cpp',
           'src/arp.cpp',
           'src/icmp.cpp',
           'src/main.cpp',
           include_directories : [ thuscnet_inc ],
           install : true)
