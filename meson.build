project('thuscnet', 'cpp',
  version : '3.0-rc',)

thuscnet_inc = include_directories('include')

executable('thuscnet',
           'src/utilities.cpp',
           'src/pcap.cpp',
           'src/ethernet.cpp',
           'src/ip.cpp',
           'src/arp.cpp',
           'src/main.cpp',
           include_directories : [ thuscnet_inc ],
           install : true)
