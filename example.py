# -*- coding: utf-8 -*-
"""Example to use python-masscan."""
import sys

import masscan

try:
    mas = masscan.PortScanner()
except masscan.PortScannerError:
    print("masscan binary not found", sys.exc_info()[0])
    sys.exit(1)
except:
    print("Unexpected error:", sys.exc_info()[0])
    sys.exit(1)

print("masscan version: {}".format(mas.masscan_version))
mas.scan('192.168.1.1', ports='T:80,1900')
print("masscan command line: {}".format(mas.command_line))
print('maascan has_host: {}'.format(mas.has_host("192.168.1.1")))
print(mas.scan_result)
for host in mas.all_hosts:
    print("Host: %s %s" % (host, mas[host]))

