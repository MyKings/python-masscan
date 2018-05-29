#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import re
import shlex
import subprocess
import sys
import logging


from xml.etree import ElementTree as ET
from multiprocessing import Process


FORMAT = '[%(asctime)-15s] [%(levelname)s] [%(filename)s %(levelno)s line] %(message)s'
logger = logging.getLogger(__file__)
logging.basicConfig(format=FORMAT)
logger.setLevel(logging.DEBUG)


class NetworkConnectionError(Exception):
    pass


PORTS = "1,3-4,6-7,9,13,17,19-26,30,32-33,37,42-43,49,53,70,79-85,88-90,99-100,106,109-111,113,119,125,135,139,143-144," \
        "146,161,163,179,199,211-212,222,254-256,259,264,280,301,306,311,340,366,389,406-407,416-417,425,427,443-445,458," \
        "464-465,481,497,500,512-515,524,541,543-545,548,554-555,563,587,593,616-617,625,631,636,646,648,666-668,683,687," \
        "691,700,705,711,714,720,722,726,749,765,777,783,787,800-801,808,843,873,880,888,898,900-903,911-912,981,987,990," \
        "992-993,995,999-1002,1007,1009-1011,1021-1100,1102,1104-1108,1110-1114,1117,1119,1121-1124,1126,1130-1132,1137-1138," \
        "1141,1145,1147-1149,1151-1152,1154,1163-1166,1169,1174-1175,1183,1185-1187,1192,1198-1199,1201,1213,1216-1218," \
        "1233-1234,1236,1244,1247-1248,1259,1271-1272,1277,1287,1296,1300-1301,1309-1311,1322,1328,1334,1352,1417," \
        "1433-1434,1443,1455,1461,1494,1500-1501,1503,1521,1524,1533,1556,1580,1583,1594,1600,1641,1658,1666,1687-1688," \
        "1700,1717-1721,1723,1755,1761,1782-1783,1801,1805,1812,1839-1840,1862-1864,1875,1900,1914,1935,1947,1971-1972," \
        "1974,1984,1998-2010,2013,2020-2022,2030,2033-2035,2038,2040-2043,2045-2049,2065,2068,2099-2100,2103,2105-2107," \
        "2111,2119,2121,2126,2135,2144,2160-2161,2170,2179,2190-2191,2196,2200,2222,2251,2260,2288,2301,2323,2366,2381-2383," \
        "2393-2394,2399,2401,2492,2500,2522,2525,2557,2601-2602,2604-2605,2607-2608,2638,2701-2702,2710,2717-2718,2725," \
        "2800,2809,2811,2869,2875,2909-2910,2920,2967-2968,2998,3000-3001,3003,3005-3007,3011,3013,3017,3030-3031,3050," \
        "3052,3071,3077,3128,3168,3211,3221,3260-3261,3268-3269,3283,3300-3301,3306,3322-3325,3333,3351,3367,3369-3372," \
        "3389-3390,3404,3476,3493,3517,3527,3546,3551,3580,3659,3689-3690,3703,3737,3766,3784,3800-3801,3809,3814," \
        "3826-3828,3851,3869,3871,3878,3880,3889,3905,3914,3918,3920,3945,3971,3986,3995,3998,4000-4006,4045,4111," \
        "4125-4126,4129,4224,4242,4279,4321,4343,4443-4446,4449,4550,4567,4662,4848,4899-4900,4998,5000-5004,5009," \
        "5030,5033,5050-5051,5054,5060-5061,5080,5087,5100-5102,5120,5190,5200,5214,5221-5222,5225-5226,5269,5280," \
        "5298,5357,5405,5414,5431-5432,5440,5500,5510,5544,5550,5555,5560,5566,5631,5633,5666,5678-5679,5718,5730," \
        "5800-5802,5810-5811,5815,5822,5825,5850,5859,5862,5877,5900-5904,5906-5907,5910-5911,5915,5922,5925,5950,5952," \
        "5959-5963,5987-5989,5998-6007,6009,6025,6059,6100-6101,6106,6112,6123,6129,6156,6346,6389,6502,6510,6543,6547," \
        "6565-6567,6580,6646,6666-6669,6689,6692,6699,6779,6788-6789,6792,6839,6881,6901,6969,7000-7002,7004,7007,7019," \
        "7025,7070,7100,7103,7106,7200-7201,7402,7435,7443,7496,7512,7625,7627,7676,7741,7777-7778,7800,7911,7920-7921," \
        "7937-7938,7999-8002,8007-8011,8021-8022,8031,8042,8045,8080-8090,8093,8099-8100,8180-8181,8192-8194,8200,8222," \
        "8254,8290-8292,8300,8333,8383,8400,8402,8443,8500,8600,8649,8651-8652,8654,8701,8800,8873,8888,8899,8994," \
        "9000-9003,9009-9011,9040,9050,9071,9080-9081,9090-9091,9099-9103,9110-9111,9200,9207,9220,9290,9415,9418,9485," \
        "9500,9502-9503,9535,9575,9593-9595,9618,9666,9876-9878,9898,9900,9917,9943-9944,9968,9998-10004,10009-10010,10012," \
        "10024-10025,10082,10180,10215,10243,10566,10616-10617,10621,10626,10628-10629,10778,11110-11111,11967,12000,12174," \
        "12265,12345,13456,13722,13782-13783,14000,14238,14441-14442,15000,15002-15004,15660,15742,16000-16001,16012,16016," \
        "16018,16080,16113,16992-16993,17877,17988,18040,18101,18988,19101,19283,19315,19350,19780,19801,19842,20000,20005," \
        "20031,20221-20222,20828,21571,22939,23502,24444,24800,25734-25735,26214,27000,27352-27353,27355-27356,27715,28201," \
        "30000,30718,30951,31038,31337,32768-32785,33354,33899,34571-34573,35500,38292,40193,40911,41511,42510,44176,44442-44443," \
        "44501,45100,48080,49152-49161,49163,49165,49167,49175-49176,49400,49999-50003,50006,50300,50389,50500,50636,50800,51103," \
        "51493,52673,52822,52848,52869,54045,54328,55055-55056,55555,55600,56737-56738,57294,57797,58080,60020,60443,61532,61900,62078,63331,64623,64680,65000,65129,65389"


def __scan_progressive__(self, hosts, ports, arguments, callback, sudo):
    """
    Used by PortScannerAsync for callback
    """
    try:
        scan_data = self._nm.scan(hosts, ports, arguments, sudo)
    except PortScannerError:
        scan_data = None

    if callback is not None:
        callback(hosts, scan_data)


class PortScanner(object):
    """
    PortScanner class allows to use masscan from python

    """

    def __init__(self, masscan_search_path=('masscan', '/usr/bin/masscan', '/usr/local/bin/masscan', '/sw/bin/masscan', '/opt/local/bin/masscan')):
        """
        Initialize PortScanner module

        * detects masscan on the system and masscan version
        * may raise PortScannerError exception if masscan is not found in the path

        :param masscan_search_path: tupple of string where to search for masscan executable. Change this if you want to use a specific version of masscan.
        :returns: nothing

        """
        self._masscan_path = ''                # masscan path
        self._scan_result = {}
        self._masscan_version_number = 0       # masscan version number
        self._masscan_subversion_number = 0    # masscan subversion number
        self._masscan_revised_number = 0    # masscan revised number
        self._masscan_last_output = ''  # last full ascii masscan output
        self._args = ''
        self._scaninfo = {}
        is_masscan_found = False       # true if we have found masscan

        self.__process = None

        # regex used to detect masscan (http or https)
        regex = re.compile(
            'Masscan version [0-9]*\.[0-9]*[^ ]* \( http(|s)://.* \)'
        )
        # launch 'masscan -V', we wait after
        # 'Masscan version 1.0.3 ( https://github.com/robertdavidgraham/masscan )'
        # This is for Mac OSX. When idle3 is launched from the finder, PATH is not set so masscan was not found
        for masscan_path in masscan_search_path:
            try:
                if sys.platform.startswith('freebsd') \
                   or sys.platform.startswith('linux') \
                   or sys.platform.startswith('darwin'):
                    p = subprocess.Popen([masscan_path, '-V'],
                                         bufsize=10000,
                                         stdout=subprocess.PIPE,
                                         close_fds=True)
                else:
                    p = subprocess.Popen([masscan_path, '-V'],
                                         bufsize=10000,
                                         stdout=subprocess.PIPE)

            except OSError:
                pass
            else:
                self._masscan_path = masscan_path  # save path
                break
        else:
            raise PortScannerError(
                'masscan program was not found in path. PATH is : {0}'.format(os.getenv('PATH'))
            )

        self._masscan_last_output = bytes.decode(p.communicate()[0])  # sav stdout
        for line in self._masscan_last_output.split(os.linesep):
            if regex.match(line):
                is_masscan_found = True
                # Search for version number
                regex_version = re.compile(r'(?P<version>\d{1,4})\.(?P<subversion>\d{1,4})\.(?P<revised>\d{1,4})')
                rv = regex_version.search(line)

                if rv:
                    # extract version/subversion/revised
                    self._masscan_version_number = int(rv.group('version'))
                    self._masscan_subversion_number = int(rv.group('subversion'))
                    self._masscan_revised_number = int(rv.group('revised'))
                break

        if not is_masscan_found:
            raise PortScannerError('masscan program was not found in path')

    def __getitem__(self, host):
        """
        returns a host detail
        """
        if sys.version_info[0] == 2:
            assert type(host) in (str, unicode), 'Wrong type for [host], should be a string [was {0}]'.format(type(host))
        else:
            assert type(host) is str, 'Wrong type for [host], should be a string [was {0}]'.format(type(host))
        return self._scan_result['scan'][host]

    @property
    def get_masscan_last_output(self):
        """
        Returns the last text output of masscan in raw text
        this may be used for debugging purpose

        :returns: string containing the last text output of masscan in raw text
        """
        return self._masscan_last_output

    @property
    def masscan_version(self):
        """
        returns masscan version if detected (int version, int subversion)
        or (0, 0) if unknown
        :returns: masscan_version_number, masscan_subversion_number
        """
        return self._masscan_version_number, self._masscan_subversion_number, self._masscan_revised_number

    @property
    def all_hosts(self):
        """
        returns a sorted list of all hosts
        """
        if not 'scan' in list(self._scan_result.keys()):
            return []
        listh = list(self._scan_result['scan'].keys())
        listh.sort()
        return listh

    @property
    def command_line(self):
        """
        returns command line used for the scan

        may raise AssertionError exception if called before scanning
        """
        assert 'masscan' in self._scan_result, 'Do a scan before trying to get result !'
        assert 'command_line' in self._scan_result['masscan'], 'Do a scan before trying to get result !'

        return self._scan_result['masscan']['command_line']

    @property
    def scan_result(self):
        """
        returns command line used for the scan

        may raise AssertionError exception if called before scanning
        """
        assert 'masscan' in self._scan_result, 'Do a scan before trying to get result !'

        return self._scan_result

    @property
    def scaninfo(self):
        """
        returns scaninfo structure
        {'tcp': {'services': '22', 'method': 'connect'}}

        may raise AssertionError exception if called before scanning
        """
        return self._scaninfo

    @property
    def scanstats(self):
        """
        returns scanstats structure
        {'uphosts': '3', 'timestr': 'Thu Jun  3 21:45:07 2010', 'downhosts': '253', 'totalhosts': '256', 'elapsed': '5.79'}

        may raise AssertionError exception if called before scanning
        """
        assert 'masscan' in self._scan_result, 'Do a scan before trying to get result !'
        assert 'scanstats' in self._scan_result['masscan'], 'Do a scan before trying to get result !'

        return self._scan_result['masscan']['scanstats']

    def scan(self, hosts='127.0.0.1', ports=PORTS, arguments='', sudo=False):
        """
        Scan given hosts

        May raise PortScannerError exception if masscan output was not xml

        Test existance of the following key to know
        if something went wrong : ['masscan']['scaninfo']['error']
        If not present, everything was ok.

        :param hosts: string for hosts as masscan use it 'scanme.masscan.org' or '198.116.0-255.1-127' or '216.163.128.20/20'
        :param ports: string for ports as masscan use it '22,53,110,143-4564'
        :param arguments: string of arguments for masscan '-sU -sX -sC'
        :param sudo: launch masscan with sudo if True

        :returns: scan_result as dictionnary
        """
        if sys.version_info[0] == 2:
            assert type(hosts) in (str, unicode), 'Wrong type for [hosts], should be a string [was {0}]'.format(type(hosts))  # noqa
            assert type(ports) in (str, unicode, type(None)), 'Wrong type for [ports], should be a string [was {0}]'.format(type(ports))  # noqa
            assert type(arguments) in (str, unicode), 'Wrong type for [arguments], should be a string [was {0}]'.format(type(arguments))  # noqa
        else:
            assert type(hosts) is str, 'Wrong type for [hosts], should be a string [was {0}]'.format(type(hosts))  # noqa
            assert type(ports) in (str, type(None)), 'Wrong type for [ports], should be a string [was {0}]'.format(type(ports))  # noqa
            assert type(arguments) is str, 'Wrong type for [arguments], should be a string [was {0}]'.format(type(arguments))  # noqa

        h_args = shlex.split(hosts)
        f_args = shlex.split(arguments)

        # Launch scan
        args = [self._masscan_path, '-oX', '-'] + h_args + ['-p', ports]*(ports is not None) + f_args

        logger.debug('Scan parameters: "' + ' '.join(args) + '"')
        self._args = ' '.join(args)

        if sudo:
            args = ['sudo'] + args

        p = subprocess.Popen(args,
                             bufsize=100000,
                             stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE
                             )

        # wait until finished
        # get output
        self._masscan_last_output, masscan_err = p.communicate()
        self._masscan_last_output = bytes.decode(self._masscan_last_output)
        masscan_err = bytes.decode(masscan_err)

        # If there was something on stderr, there was a problem so abort...  in
        # fact not always. As stated by AlenLPeacock :
        # This actually makes python-masscan mostly unusable on most real-life
        # networks -- a particular subnet might have dozens of scannable hosts,
        # but if a single one is unreachable or unroutable during the scan,
        # masscan.scan() returns nothing. This behavior also diverges significantly
        # from commandline masscan, which simply stderrs individual problems but
        # keeps on trucking.

        masscan_err_keep_trace = []
        masscan_warn_keep_trace = []
        if len(masscan_err) > 0:
            regex_warning = re.compile('^Warning: .*', re.IGNORECASE)
            for line in masscan_err.split(os.linesep):
                if len(line) > 0:
                    rgw = regex_warning.search(line)
                    if rgw is not None:
                        # sys.stderr.write(line+os.linesep)
                        masscan_warn_keep_trace.append(line+os.linesep)
                    else:
                        # raise PortScannerError(masscan_err)
                        masscan_err_keep_trace.append(masscan_err)

        return self.analyse_masscan_xml_scan(
            masscan_xml_output=self._masscan_last_output,
            masscan_err=masscan_err,
            masscan_err_keep_trace=masscan_err_keep_trace,
            masscan_warn_keep_trace=masscan_warn_keep_trace
        )

    def analyse_masscan_xml_scan(self, masscan_xml_output=None, masscan_err='', masscan_err_keep_trace='', masscan_warn_keep_trace=''):
        """
        Analyses NMAP xml scan ouput

        May raise PortScannerError exception if masscan output was not xml

        Test existance of the following key to know if something went wrong : ['masscan']['scaninfo']['error']
        If not present, everything was ok.

        :param masscan_xml_output: xml string to analyse
        :returns: scan_result as dictionnary
        """

        # masscan xml output looks like :
        """
        <?xml version="1.0"?>
        <!-- masscan v1.0 scan -->
        <?xml-stylesheet href="" type="text/xsl"?>
        <nmaprun scanner="masscan" start="1490242774" version="1.0-BETA"  xmloutputversion="1.03">
            <scaninfo type="syn" protocol="tcp" />
            <host endtime="1490242774">
                <address addr="10.0.9.9" addrtype="ipv4"/>
                <ports>
                    <port protocol="tcp" portid="80">
                        <state state="open" reason="syn-ack" reason_ttl="64"/>
                    </port>
                </ports>
                </host>
            <host endtime="1490242774"><address addr="10.0.9.254" addrtype="ipv4"/><ports><port protocol="tcp" portid="80"><state state="open" reason="syn-ack" reason_ttl="255"/></port></ports></host>
            <host endtime="1490242774"><address addr="10.0.9.19" addrtype="ipv4"/><ports><port protocol="tcp" portid="80"><state state="open" reason="syn-ack" reason_ttl="64"/></port></ports></host>
            <host endtime="1490242774"><address addr="10.0.9.49" addrtype="ipv4"/><ports><port protocol="tcp" portid="80"><state state="open" reason="syn-ack" reason_ttl="64"/></port></ports></host>
            <host endtime="1490242774"><address addr="10.0.9.8" addrtype="ipv4"/><ports><port protocol="tcp" portid="80"><state state="open" reason="syn-ack" reason_ttl="64"/></port></ports></host>
            <host endtime="1490242775"><address addr="10.0.9.11" addrtype="ipv4"/><ports><port protocol="tcp" portid="80"><state state="open" reason="syn-ack" reason_ttl="64"/></port></ports></host>
            <host endtime="1490242775"><address addr="10.0.9.10" addrtype="ipv4"/><ports><port protocol="tcp" portid="80"><state state="open" reason="syn-ack" reason_ttl="64"/></port></ports></host>
            <host endtime="1490242775"><address addr="10.0.9.6" addrtype="ipv4"/><ports><port protocol="tcp" portid="80"><state state="open" reason="syn-ack" reason_ttl="64"/></port></ports></host>
            <host endtime="1490242775"><address addr="10.0.9.12" addrtype="ipv4"/><ports><port protocol="tcp" portid="80"><state state="open" reason="syn-ack" reason_ttl="64"/></port></ports></host>
            <host endtime="1490242776"><address addr="10.0.9.28" addrtype="ipv4"/><ports><port protocol="tcp" portid="80"><state state="open" reason="syn-ack" reason_ttl="64"/></port></ports></host>
            <host endtime="1498802982"><address addr="10.0.9.29" addrtype="ipv4"/><ports><port protocol="tcp" portid="80"><state state="open" reason="response" reason_ttl="48"/><service name="title" banner="401 - Unauthorized"></service></port></ports></host>
            <runstats>
                <finished time="1490242786" timestr="2017-03-23 12:19:46" elapsed="13" />
                <hosts up="10" down="0" total="10" />
            </runstats>
        </nmaprun>
        """

        if masscan_xml_output is not None:
            self._masscan_last_output = masscan_xml_output

        scan_result = {}

        try:
            dom = ET.fromstring(self._masscan_last_output)
        except ET.ParseError:
            if "found=0" in masscan_err:
                raise NetworkConnectionError("network is unreachable.")
            raise ET.ParseError
        except Exception:
            if len(masscan_err) > 0:
                raise PortScannerError(masscan_err)
            else:
                raise PortScannerError(self._masscan_last_output)

        # masscan command line
        scan_result['masscan'] = {
            'command_line': self._args,
            'scanstats': {
                'timestr': dom.find("runstats/finished").get('timestr'),
                'elapsed': dom.find("runstats/finished").get('elapsed'),
                'uphosts': dom.find("runstats/hosts").get('up'),
                'downhosts': dom.find("runstats/hosts").get('down'),
                'totalhosts': dom.find("runstats/hosts").get('total')}
            }

        # if there was an error
        if len(masscan_err_keep_trace) > 0:
            self._scaninfo['error'] = masscan_err_keep_trace

        # if there was a warning
        if len(masscan_warn_keep_trace) > 0:
            self._scaninfo['warning'] = masscan_warn_keep_trace

        scan_result['scan'] = {}

        for dhost in dom.findall('host'):
            # host ip, mac and other addresses
            host = None
            address_block = {}
            vendor_block = {}
            for address in dhost.findall('address'):
                addtype = address.get('addrtype')
                address_block[addtype] = address.get('addr')
                if addtype == 'ipv4':
                    host = address_block[addtype]
                elif addtype == 'mac' and address.get('vendor') is not None:
                    vendor_block[address_block[addtype]] = address.get('vendor')

            if host is None:
                host = dhost.find('address').get('addr')
            if host not in scan_result['scan']:
                scan_result['scan'][host] = {}

            for dport in dhost.findall('ports/port'):
                proto = dport.get('protocol')
                port = int(dport.get('portid'))
                state = dport.find('state').get('state')
                reason = dport.find('state').get('reason')
                reason_ttl = dport.find('state').get('reason_ttl')
                services = []

                if not proto in list(scan_result['scan'][host].keys()):
                    scan_result['scan'][host][proto] = {}

                scan_result['scan'][host][proto][port] = {
                    'state': state,
                    'reason': reason,
                    'reason_ttl': reason_ttl,
                }

                for service in dhost.findall('ports/port/service'):
                    services.append({
                        'name': service.get('name'),
                        'banner': service.get('banner'),
                    })
                scan_result['scan'][host][proto][port]['services'] = services

        self._scan_result = scan_result
        return scan_result

    def has_host(self, host):
        """
        returns True if host has result, False otherwise
        """
        assert type(host) is str, 'Wrong type for [host], should be a string [was {0}]'.format(type(host))
        assert 'scan' in self._scan_result, 'Do a scan before trying to get result !'

        if host in list(self._scan_result['scan'].keys()):
            return True

        return False


class PortScannerAsync(object):
    """
    PortScannerAsync allows to use masscan from python asynchronously
    for each host scanned, callback is called with scan result for the host

    """
    def __init__(self):
        """
        Initialize the module

        * detects masscan on the system and masscan version
        * may raise PortScannerError exception if masscan is not found in the path

        """
        self._process = None
        self._nm = PortScanner()
        return

    def __del__(self):
        """
        Cleanup when deleted

        """
        if self._process is not None:
            try:
                if self._process.is_alive():
                    self._process.terminate()
            except AssertionError:
                # Happens on python3.4
                # when using PortScannerAsync twice in a row
                pass

        self._process = None
        return

    def scan(self, hosts='127.0.0.1', ports=None, arguments='', callback=None, sudo=False):
        """
        Scan given hosts in a separate process and return host by host result using callback function

        PortScannerError exception from standard masscan is catched and you won't know about but get None as scan_data

        :param hosts: string for hosts as masscan use it 'scanme.masscan.org' or '198.116.0-255.1-127' or '216.163.128.20/20'
        :param ports: string for ports as masscan use it '22,53,110,143-4564'
        :param arguments: string of arguments for masscan '-sU -sX -sC'
        :param callback: callback function which takes (host, scan_data) as arguments
        :param sudo: launch masscan with sudo if true
        """

        if sys.version_info[0] == 2:
            assert type(hosts) in (str, unicode), 'Wrong type for [hosts], should be a string [was {0}]'.format(type(hosts))
            assert type(ports) in (str, unicode, type(None)), 'Wrong type for [ports], should be a string [was {0}]'.format(type(ports))
            assert type(arguments) in (str, unicode), 'Wrong type for [arguments], should be a string [was {0}]'.format(type(arguments))
        else:
            assert type(hosts) is str, 'Wrong type for [hosts], should be a string [was {0}]'.format(type(hosts))
            assert type(ports) in (str, type(None)), 'Wrong type for [ports], should be a string [was {0}]'.format(type(ports))
            assert type(arguments) is str, 'Wrong type for [arguments], should be a string [was {0}]'.format(type(arguments))

        assert callable(callback) or callback is None, 'The [callback] {0} should be callable or None.'.format(str(callback))

        self._process = Process(
            target=__scan_progressive__,
            args=(self, hosts, ports, arguments, callback, sudo)
            )
        self._process.daemon = True
        self._process.start()

    def stop(self):
        """
        Stop the current scan process

        """
        if self._process is not None:
            self._process.terminate()
        return

    def wait(self, timeout=None):
        """
        Wait for the current scan process to finish, or timeout

        :param timeout: default = None, wait timeout seconds

        """
        assert type(timeout) in (int, type(None)), 'Wrong type for [timeout], should be an int or None [was {0}]'.format(type(timeout))

        self._process.join(timeout)
        return

    def still_scanning(self):
        """
        :returns: True if a scan is currently running, False otherwise

        """
        try:
            return self._process.is_alive()
        except:
            return False


class PortScannerYield(PortScannerAsync):
    """
    PortScannerYield allows to use masscan from python with a generator
    for each host scanned, yield is called with scan result for the host

    """

    def __init__(self):
        """
        Initialize the module

        * detects masscan on the system and masscan version
        * may raise PortScannerError exception if masscan is not found in the path

        """
        PortScannerAsync.__init__(self)
        return

    def scan(self, hosts='127.0.0.1', ports=None, arguments='', sudo=False):
        """
        Scan given hosts in a separate process and return host by host result using callback function

        PortScannerError exception from standard masscan is catched and you won't know about it

        :param hosts: string for hosts as masscan use it 'scanme.masscan.org' or '198.116.0-255.1-127' or '216.163.128.20/20'
        :param ports: string for ports as masscan use it '22,53,110,143-4564'
        :param arguments: string of arguments for masscan '-sU -sX -sC'
        :param callback: callback function which takes (host, scan_data) as arguments
        :param sudo: launch masscan with sudo if true

        """

        assert type(hosts) is str, 'Wrong type for [hosts], should be a string [was {0}]'.format(type(hosts))
        assert type(ports) in (str, type(None)), 'Wrong type for [ports], should be a string [was {0}]'.format(type(ports))
        assert type(arguments) is str, 'Wrong type for [arguments], should be a string [was {0}]'.format(type(arguments))

        for host in self._nm.listscan(hosts):
            try:
                scan_data = self._nm.scan(host, ports, arguments, sudo)
            except PortScannerError:
                scan_data = None
            yield (host, scan_data)
        return

    def stop(self):
        pass

    def wait(self, timeout=None):
        pass

    def still_scanning(self):
        pass


class PortScannerError(Exception):
    """
    Exception error class for PortScanner class

    """
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)

    def __repr__(self):
        return 'PortScannerError exception {0}'.format(self.value)
