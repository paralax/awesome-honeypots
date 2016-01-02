#!/usr/bin/env python

import re
import sys
import urllib2

with open(sys.argv[1], 'r') as f:
    for line in f.readlines():
        if '](http' in line:
            for url in re.findall("(http[s?]://[^)]+)", line):
                # print url
                try:
                    request = urllib2.Request(url)
                    request.get_method = lambda : 'HEAD'
                    resp = urllib2.urlopen(request)
                    if resp.getcode() != 200:
                        print 'ERROR - ', line
                except urllib2.URLError, e:
                    print e, line