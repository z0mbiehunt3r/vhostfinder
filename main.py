#!/usr/bin/env python
#coding:utf-8


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

'''
Frank Lopez: You know what a chazzer is? 
Tony Montana: No, Frank, you tell me. What is a chazzer? 
Frank Lopez: It's a Yiddish word for "pig."
            See, the guy, he wants more than what he needs.
            He don't fly straight no more. 

                            Scarface (1983)
'''

import datetime
import os
import sys

try:
    import argparse
except ImportError:
    print 'You need argparse (http://code.google.com/p/argparse/)'
    sys.exit(-1)

from vhostfinder import vhostfinder

#----------------------------------------------------------------------
def _banner():
    banner = '''
        |----------------------------------------------------------|
        |                        vhostfinder                       |
        |               Alejandro Nolla (z0mbiehunt3r)             |
        |----------------------------------------------------------|\n'''
    
    print banner

#----------------------------------------------------------------------
def _check_arguments():    
    if len(sys.argv) < 7:
        parser.print_help()
        sys.exit(-1)

#----------------------------------------------------------------------
def _read_oneliner_file(file_name):
    """
    Read given text file and returns his content as a list,
    one line per position
    
    @param file_name: File to read
    @type file_name: str
    
    @return: List of readed lines
    @rtype:list
    """
    
    fd = open(file_name, mode='r')
    lines = fd.readlines()
    fd.close()
    
    lines = map(str.rstrip, lines) # remove trailing whitespace
    lines = list(set(lines)) # remove any duplicate
    
    return lines



if __name__=='__main__':
    
    _banner()
    
    # Create argument parser
    parser = argparse.ArgumentParser(description='Enumerate virtual hosts against several IP addresses / netranges', add_help=False)
    
    gr1 = parser.add_argument_group('Main arguments')
    gr1.add_argument('-d', '--domain', dest='domain', required=True, help='Domain to enumerate')
    gr1.add_argument('-i', '--input', dest='netrangefile', required=True, help='File with netranges')
    gr1.add_argument('-o', '--output', dest='outputdir', required=True, help='Output directory')
    gr1.add_argument('--vhosts', dest='vhostsfile', required=True, help='File with virtual hosts')
    
    gr2 = parser.add_argument_group('Optional arguments')
    gr2.add_argument('-p', '--proxies', dest='proxiefile', required=False, help='File with proxies')
    gr2.add_argument('-t', '--threads', dest='concurrentreq', required=False, type=int, default=50, help='Concurrent HTTP(S) requests')
    gr2.add_argument('-v', '--verbose', dest='verbositylevel', required=False, action='count', default=0, help='Verbosity level (up to -vv)')
    gr2.add_argument('-c', '--colours', dest='colours', required=False, default=False,  action='store_true', help='Coloured output')
    gr2.add_argument('--timeout', dest='timeout', required=False, type=int, default=10, help='HTTP timeout')
    gr2.add_argument('--ssl', dest='usessl', required=False, default=False,  action='store_true', help='Use HTTPS instead of HTTP')
    
    # Check if enough arguments are given
    _check_arguments()
    
    # Parse arguments
    args = parser.parse_args()
    
    if args.outputdir[-1] != '/': # force output dir ends with /
        args.outputdir += '/'
    
    try:
        ip_addresses = vhostfinder.parse_network_ranges(args.netrangefile)
        virtual_hosts = _read_oneliner_file(args.vhostsfile)
        
        if args.proxiefile:
            proxies_list = _read_oneliner_file(args.proxiefile)
        else:
            proxies_list = None
        
        vhf = vhostfinder.VirtualHostFinder(args.domain, args.concurrentreq, args.timeout, args.verbositylevel, args.colours)
        
        if args.colours:
            print vhostfinder.COLORS['INFO']+'[*] %i total IP addresses and %i virtual hosts to enumerate'%(len(ip_addresses), len(virtual_hosts))+vhostfinder.COLORS['RESTORE']
        else:
            print '[*] %i total IP addresses and %i virtual hosts to enumerate'%(len(ip_addresses), len(virtual_hosts))

        vhf.enumerate_virtual_hosts(ip_addresses, virtual_hosts, args.usessl, proxies_list) # make HTTP(S) requests 
        
        if args.colours:
            print vhostfinder.COLORS['INFO']+'[*] Writing CSV report to %s...' %args.outputdir
        else:
            print '[*] Writing CSV report to %s...' %args.outputdir
            
            
        if not os.path.exists(args.outputdir):
            os.makedirs(args.outputdir)
        
        vhf.generate_csv_report(args.outputdir)
        
        if args.colours:
            print vhostfinder.COLORS['INFO']+'[*] Writing HTML responses to %s...' %args.outputdir+vhostfinder.COLORS['RESTORE']
        else:
            print '[*] Writing HTML responses to %s...' %args.outputdir
        vhf.write_html_responses(args.outputdir)
        
        if args.colours:
            print vhostfinder.COLORS['INFO']+'[-] Finished'+vhostfinder.COLORS['RESTORE']
        else:
            print '[-] Finished'
        
    except KeyboardInterrupt:
        if args.colours:
            print vhostfinder.COLORS['INFO']+'Exiting...'+vhostfinder.COLORS['RESTORE']
        else:
            print 'Exiting...'
        sys.exit()
