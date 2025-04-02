project('thuscnet', 'cpp',
  version : '2.0',)

thuscnet_inc = include_directories('include')

executable('thuscnet',
           'src/utilities.cpp',
           'src/pcap.cpp',
           'src/ethernet.cpp',
           'src/ip.cpp',
           'src/main.cpp',
           include_directories : [ thuscnet_inc ],
           install : true)
