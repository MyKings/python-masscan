#!/usr/bin/env python
# -*- coding: utf-8 -*-


import sys

import masscan

try:
    mas = masscan.PortScanner()
except masscan.PortScannerError:
    print('Masscan not found', sys.exc_info()[0])
    sys.exit(1)
except:
    print("Unexpected error:", sys.exc_info()[0])
    sys.exit(1)

print 'maascan version: ', mas.masscan_version
mas.scan('172.0.8.78/24', ports='22,80,8080')
print 'maascan command line: ', mas.command_line
#print 'maascan scaninfo: ', mas.scaninfo
#print 'maascan scanstats: ', mas.scanstats

#for host in mas.all_hosts:
#    print('Host: %s (%s)' % (host, mas[host]))
print mas.scan_result
#print mas.get_masscan_last_output
