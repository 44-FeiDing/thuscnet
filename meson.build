project('thuscnet', 'cpp',
  version : '2.0-rc',)

thuscnet_inc = include_directories('include')

executable('thuscnet',
           'src/pcap.cpp',
           'src/ethernet.cpp',
           'src/utilities.cpp',
           'src/main.cpp',
           include_directories : [ thuscnet_inc ],
           install : true)
