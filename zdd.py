#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
#  Check SPF results and provide recommended action back to Postfix.
#
#  Tumgreyspf source
#  Copyright © 2004-2005, Sean Reifschneider, tummy.com, ltd.
#  <jafo@tummy.com>
#
#  pypolicyd-spf
#  Copyright © 2007-16, Scott Kitterman <scott@kitterman.com>
'''
   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
'''

def main():
    __version__ = "0.0.1"

    import syslog
    import os
    import socket
    import sys
    import re
    import requests
    import whois
    from datetime import timedelta,datetime,time


    if int(sys.version_info.major) < 3 or (int(sys.version_info.major) == 3 and \
            int(sys.version_info.minor) < 3):
        raise ImportError("Python 3.3 or later is required")

    syslog.openlog(os.path.basename(sys.argv[0]), syslog.LOG_PID, syslog.LOG_MAIL)


    #  loop reading data  {{{1
    debugLevel = 1
    if debugLevel >= 3: syslog.syslog('Starting')
    instance_dict = {'0':'init',}
    instance_dict.clear()
    data = {}
    domain_check = {}
    lineRx = re.compile(r'^\s*([^=\s]+)\s*=(.*)$')
    mailRx = re.compile(r'^\s*([^@\s]+)\s*@(.*)$')
    while 1:
        # Python readline assumes ascii here, but sometimes it's not
        lineraw = sys.stdin.buffer.readline()
        line = lineraw.decode('UTF-8',errors='replace')
        if not line: break
        line = line.rstrip()
        if debugLevel >= 4: syslog.syslog('Read line: "%s"' % line)

        #  end of entry  {{{2
        if not line:
            if 'sender' in data.keys(): 
                sender = data.get('sender')
                em = mailRx.match(sender)
                user = em.group(1)
                domain = em.group(2)
                
                try:
                    p = whois.whois(domain)
                    creation_date  = p.get('creation_date')
                    if debugLevel >= 3: syslog.syslog('Whois query ok')
                except:
                    creation_date = datetime(1970,1,1)
                    if debugLevel >= 1: syslog.syslog('Error on whois query')
               

                if isinstance(creation_date,list):
                    vdata = creation_date[0]
                elif isinstance(creation_date,str):
                    print(creation_date,"strig")
                elif isinstance(creation_date,datetime):
                    vdata = creation_date

                difference = (datetime.now() - vdata)
                difference = int(difference.total_seconds())
                
                if debugLevel >= 1: syslog.syslog('Found domain: %s user %s Domain AGE %d' % (domain,user,difference))
                if debugLevel >= 4: syslog.syslog('Found the end of entry')
                if difference<int(86400*7):
                    check = False
                else:
                    check = True

                if not check:
                    sys.stdout.write('action=reject #NEW DOMAIN\n\n')
                else:
                    sys.stdout.write('action=dunno\n\n')
            #  end of record  {{{3
            sys.stdout.flush()
            data = {}
            continue
        #  parse line  {{{2
        m = lineRx.match(line)
        if not m: 
            if debugLevel >= 0: syslog.syslog('ERROR: Could not match line "%s"' % line)
            continue
        #  save the string  {{{2
        key = m.group(1)
        value = m.group(2)
        if key not in [ 'protocol_state', 'protocol_name', 'queue_id' ]:
            value = value.lower()
        data[key] = value
    if debugLevel >= 3: syslog.syslog('Normal exit')

main()