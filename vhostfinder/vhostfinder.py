__license__= '''
vhostfinder - Enumerates virtual hosts against several ip addresses

Copyright (C) 2013  Alejandro Nolla Blanco - alejandro.nolla@gmail.com 
Nick: z0mbiehunt3r - Twitter: https://twitter.com/z0mbiehunt3r
Blog: navegandoentrecolisiones.blogspot.com


This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
'''

__version__ = '0.5'

import csv
import datetime
import Queue
import random
import re
import urlparse
import socket
import sys
import threading

try:
    import requests
except ImportError:
    print 'You need requests (https://pypi.python.org/pypi/requests)'
    sys.exit(-1)

try:
    import iptools
except ImportError:
    print 'You need iptools (https://pypi.python.org/pypi/iptools/)'
    sys.exit(-1)

USERAGENT = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'
COLORS = {'INFO':chr(27)+'[0;93m',
          'LESS': chr(27)+'[0;34m',
          'PLUS':chr(27)+'[0;32m',
          'ERROR': chr(27)+'[0;31m',
          'PLUS02': chr(27)+'[0;35m',
          'RESTORE': '\x1b[0m'}


#----------------------------------------------------------------------
def parse_network_ranges(netranges_file):
    """
    Read a textfile with network ranges and create a list of IP addresses
    
    @param netranges_file: Path to text file with netranges to parse
    @type: str
    
    @return: List of IP addresses
    @rtype: list
    """
    
    network_ranges = []
    
    text = open(netranges_file, mode='r').read()
    # Find netranges
    netranges = re.findall(r'(\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})-(\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})', text)
    cidr_ranges = re.findall(r'\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}/\d{1,2}', text)
    # Match at the beginning of each line instead of all text -> http://docs.python.org/2/library/re.html#re.MULTILINE
    ip_addresses = re.findall(r'(^\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})\s*', text, flags=re.MULTILINE)
    
    # Validate them
    cidr_ranges = [cidr_range for cidr_range in cidr_ranges if iptools.validate_cidr(cidr_range)]
    netranges = [netrange for netrange in netranges if iptools.validate_ip(netrange[0]) and iptools.validate_ip(netrange[1])]
    ip_addresses = [ip_address for ip_address in ip_addresses if iptools.validate_ip(ip_address)]
    
    # Not a real good approaching...
    iptools_cidr_ranges = [iptools.IpRange(iptools_cidr_range) for iptools_cidr_range in cidr_ranges]
    iptools_netranges = [iptools.IpRange(netrange) for netrange in netranges]
    iptools_ip_addreses_range = [iptools.IpRange(ip_address) for ip_address in ip_addresses]
    
    network_ranges.extend(iptools_cidr_ranges)
    network_ranges.extend(iptools_netranges)
    network_ranges.extend(iptools_ip_addreses_range)
    
    # Outside loop, inside loop
    network_ranges = [ip_address for network_range in network_ranges for ip_address in network_range]
    network_ranges = list(set(network_ranges)) # avoid duplicated IP addresses (overlaped)
    
    return network_ranges


########################################################################
class VirtualHostCheckerThread(threading.Thread):
    """
    Class used to check for potential virtual hosts in several IP addresses
    Get HTTP request data from an input queue and append result to output queue
    """

    #----------------------------------------------------------------------
    def __init__(self, semaphore, input_queue, output_results, verbosity_level, use_colours=False):
        """
        Constructor
        
        @param semaphore: Semaphore to handle concurrent access
        @type semaphore: threading.BoundedSemaphore()
        
        @param input_queue: queue from get HTTP request params
        @type input_queue: Queue.queue()
        
        @param output_results: list to insert HTTP request results
        @type output_results: list
        
        @param verbosity_level: output verbosity level
        @type: verbosity_level int
        
        @param use_colours: whether use coloured output or not
        @type use_colours: bool
        """
        
        threading.Thread.__init__(self)
        self.daemon = True # to exit with ctrl c (http://docs.python.org/2/library/threading.html#threading.Thread.daemon)
        self.in_queue = input_queue
        self.semaphore = semaphore
        self.enumeration_results = output_results
        self.verbosity_level = verbosity_level
        self.use_colours = use_colours
    
    #----------------------------------------------------------------------
    def run(self):
        """
        Process input queue, make HTTP(s) request and append result to
        output queue
        """
        
        while not self.in_queue.empty():
            self.semaphore.acquire()
            
            try:
                # get item from input queue and process params
                request_data = self.in_queue.get()
                
                http_timeout = request_data['http_timeout']
                ip_address = request_data['ip_address']
                proxy = request_data['proxy']
                http_headers = request_data['http_headers']
                url = request_data['url']
                
                socket.setdefaulttimeout(http_timeout) # to avoid errors with streaming webs
                if proxy:
                    response = requests.get(url, headers=http_headers, proxies={'http':proxy, 'https':proxy},
                                            timeout=http_timeout, verify=False) # set True to check certificate
                else:
                    response = requests.get(url, headers=http_headers,
                                            timeout=http_timeout, verify=False) # set True to check certificate
                
                if response.status_code: # process only answered ones
                    
                    virtual_host = response.request.headers['Host']
                    ip_address = urlparse.urlparse(response.request.url)[1] # just to get netloc slice
                    content_length = len(response.content)
                    regex = re.search(r'<title>(.+?)</title>', response.content, re.IGNORECASE)
                    if regex is not None:
                        http_title = regex.group(1)
                    else:
                        http_title = ''
                    
                    # create dictionary with response data and append to output queue
                    vhost_dict = {'ip_address': ip_address,
                                  'virtual_host': virtual_host,
                                  'response_code': response.status_code,
                                  'response_length': content_length,
                                  'http_title': http_title,
                                  'http_content': response.content}
                    self.enumeration_results.append(vhost_dict)
                    
                    # show info to stdout
                    if self.verbosity_level > 0:
                        
                        if response.status_code == 200:
                            if self.use_colours:
                                sys.stdout.write(COLORS['PLUS']+'   [+] vhost:%s ip:%s rcode:200 rlen:%i {%s}\n' %(virtual_host, ip_address, content_length, http_title))
                            else:
                                sys.stdout.write('   [+] vhost:%s ip:%s rcode:200 rlen:%i {%s}\n' %(virtual_host, ip_address, content_length, http_title))
                        elif response.status_code in [301, 302, 401]:
                            if self.use_colours:
                                sys.stdout.write(COLORS['PLUS02']+'   [+] vhost:%s ip:%s rcode:%i rlen:%i {%s}\n' %(virtual_host, ip_address, response.status_code, content_length, http_title))
                            else:
                                sys.stdout.write('   [+] vhost:%s ip:%s rcode:%i rlen:%i {%s}\n' %(virtual_host, ip_address, response.status_code, content_length, http_title))
                    
                    if self.verbosity_level > 1: # also show negative answers
                        if self.use_colours:
                            sys.stdout.write(COLORS['ERROR']+'   [-] vhost:%s ip:%s rcode:%i rlen:%i {%s}\n' %(virtual_host, ip_address, response.status_code, content_length, http_title))
                        else:
                            sys.stdout.write('   [-] vhost:%s ip:%s rcode:%i rlen:%i {%s}\n' %(virtual_host, ip_address, response.status_code, content_length, http_title))
                        
                    if self.use_colours: sys.stdout.write(COLORS['RESTORE']) # always restore stdout colour)
            
            except Exception, e:
                pass
            
            finally:
                # always mark task as done and release lock
                self.in_queue.task_done()
                self.semaphore.release()


########################################################################
class VirtualHostFinder:
    """
    Class used to enumerate virtual hosts against several network IP addresses using
    a list of potential virtual host as 'Host' HTTP header
    """
    
    #----------------------------------------------------------------------
    def __init__(self, domain, concurrent_requests=30, request_timeout=10, verbosity_level=0, coloured_output=False):
        """
        @param domain: Domain to enumerate
        @type domain: str
        
        @param concurrent_requests: Maximum number of concurrent request
        @type concurrent_requests: int
        
        @param request_timeout: Timeout for HTTP(S) requests
        @type request_timeout: int
        
        @param verbosity_level: Verbosity level
        @type verbosity_level: int
        
        @param coloured_output: Use coloured output or not
        @type coloured_output: bool
        """
        
        self._concurrent_requests = concurrent_requests
        self._coloured_output = coloured_output
        self._domain = domain
        self._request_timeout = request_timeout
        self._verbosity_level = verbosity_level
        self._user_agent = USERAGENT
        self.enumeration_results = []

    #----------------------------------------------------------------------
    def enumerate_virtual_hosts(self, ip_addresses, virtual_hosts, use_ssl=False, proxies_list=None):
        """
        Will enumerate potential virtual hosts against given IP addresses and set
        self.enumeration_results once finished.
        
        @param domain: Domain to enumerate
        @type domain: str
        
        @param ip_addresses: List with web servers to analyze
        @type ip_addresses: list
        
        @param virtual_hosts: List with virtual hosts to check
        @type virtual_hosts: list
        
        @param concurrent_requets: Maximum number of concurrent requests
        @type concurrent_requets: int
        
        @param proxie_list: List with proxies to use (randomly chosen per request)
        @type: list
        """
        
        input_queue = Queue.Queue()
        output_results = []
        threads_list = []
        base_url = 'https://' if use_ssl else 'http://'
        
        semaphore = threading.BoundedSemaphore(self._concurrent_requests)
        
        # populate input queue
        for ip_address in ip_addresses:
            final_url = '%s%s/' %(base_url, ip_address) # something like http://127.0.0.1/
            self.enumeration_results.append({'ip':ip_address, 'vhosts':[]}) # prepopulate output list

            for virtual_host in virtual_hosts:
                request_data = { 'ip_address':ip_address,
                                 'url':final_url,
                                 'http_headers': {
                                     'Host': '%s.%s' %(virtual_host, self._domain),
                                     'User-Agent': self._user_agent},
                                 'proxy':None,
                                 'http_timeout': self._request_timeout
                            }
                
                if proxies_list:
                    request_data.update({'proxy':random.choice(proxies_list)})
                
                input_queue.put(request_data)
            
        # start making HTTP(s) requests
        for x in range(0, self._concurrent_requests):
            t = VirtualHostCheckerThread(semaphore, input_queue, output_results, self._verbosity_level, self._coloured_output)
            t.daemon = True
            threads_list.append(t)
            t.start()
        
        for thread in threads_list:
            thread.join(self._request_timeout) # isAlive isn't used but needed for daemon mode - ctrl c
            
        # Process responses
        for response in output_results:
            for pos, elem in enumerate(self.enumeration_results):
                if elem['ip'] == response['ip_address']: # populate enumeration results
                    vhost_dict = {'virtual_host': response['virtual_host'],
                                  'response_code': response['response_code'],
                                  'response_length': response['response_length'],
                                  'http_title': response['http_title'],
                                  'http_content': response['http_content']}
                    self.enumeration_results[pos]['vhosts'].append(vhost_dict) # insert response data
                    break
    
    #----------------------------------------------------------------------
    def generate_csv_report(self, output_dir):
        """
        Write a report in CSV format
        
        @param output_dir: Output dir to write CSV report
        @type output_dir: str
        """
        
        output_filename = output_dir+'%s_%s.csv' %(datetime.date.today(), self._domain)
        
        csvwriter = csv.writer(open(output_filename, mode='w'), delimiter='\t', quotechar='"', quoting=csv.QUOTE_ALL)        
        csvwriter.writerow(['ip', 'virtual_host', 'response code', 'response length', 'http title']) # write header
        
        for result in self.enumeration_results:
            for vhost in result['vhosts']:
                csvwriter.writerow([result['ip'], vhost['virtual_host'], vhost['response_code'], vhost['response_length'], vhost['http_title']])
    
    #----------------------------------------------------------------------
    def write_html_responses(self, output_dir):
        """
        Write HTML responses in given output dir, only those with
        HTTP status code of 200, 301, 302 or 401.
        
        @param output_dir: Output dir to write html responses
        @type output_dir: str
        """
        
        for result in self.enumeration_results:
            for vhost in result['vhosts']:
                if vhost['response_code'] in [200, 301, 302, 401]:
                    file_name = '%s_%s_%s-%d.html' %(datetime.date.today(), result['ip'], vhost['virtual_host'], vhost['response_code'])
                    
                    fd = open(output_dir+file_name, mode='w')
                    fd.write(vhost['http_content'])
                    fd.close()

    
