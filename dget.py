#!/usr/bin/env python
# -*- coding: utf-8 -*-

__version__ = "0.0.1"

import sys
import os
from BeautifulSoup import BeautifulSoup
from urllib2 import urlopen, HTTPError
from re import compile, escape
from SOAPpy import SOAPProxy
from optparse import OptionParser
from lib import runinDIR
from urlparse import urljoin

ca_path = '/etc/ssl/ca-debian'
if os.path.isdir(ca_path):
    os.environ['SSL_CERT_DIR'] = ca_path

def getVersions(soap_url, p):
    return SOAPProxy(soap_url).versions(source=p)._asdict()


def poolPath(pkg):
    ret = 'main/'
    if pkg.startswith('lib'): ret+='lib' + pkg[3]
    else: ret+= pkg[0]
    return '%s/%s' % (ret,pkg)


def getLink(pkg,ver):
    dscpages = ["https://tracker.debian.org/pkg/%s", "https://packages.qa.debian.org/%s",
                "http://security.debian.org/pool/updates/%s/"]

    for dscpage in dscpages:
        url = dscpage % pkg
        if 'pool' in dscpage: url = dscpage % poolPath(pkg)
        soup = BeautifulSoup(urlopen(url))
        for link in soup.findAll('a', attrs={'href': compile(escape("%s_%s.dsc" % (pkg, ver)) + '$')}):
            yield urljoin(url, link.get('href'))

def dget(pkg,ver,where):

    if sum(c.isdigit() for c in ver) == 0:
        print "We need to find a version for %s" % ver
        for d, v in getVersions('https://packages.qa.debian.org/cgi-bin/soap-alpha.cgi', pkg).iteritems():
            if v == ver or d == ver:
                print("%s_%s (%s) found!" % (pkg, v, d))
                ver = v
                break
        else:
            print("%s (%s) not found in PTS SOAP." % (pkg, ver))
            return None

    ver = ver.split(':')[-1] # Remove de epoch

    for link in getLink(pkg,ver):
        try:
            conn = urlopen(link)
        except HTTPError as e:
            print "%s: %s" %(link, e.code)
            continue
        else:
            break
    else:
        print("I cannot find %s %s.dsc anywhere" % (pkg, ver))
        return None

    print "fetching from %s" % link

    runinDIR(["/usr/bin/dget", "-x", "-u", link],where)

    src = max([ os.path.join(where,d) for d in os.listdir(where)], key=os.path.getmtime)
    return src

if __name__ == '__main__':
    opt = OptionParser(usage="1. %prog -p davfs2 -v testing\n"
                             "       2. %prog -p imagemagick -v 6.8.9.9-5+deb8u8 -d /tmp/\n"
                             "       3. env WORKING_DIR='cache/tmp' %prog -p imagemagick -v stable",
                       version="dget.py %s" % __version__)
    opt.add_option("-v", "--ver", metavar='VER', help="package name to fetch")
    opt.add_option("-p", "--pkg", metavar='PKG', help="version to fetch")
    opt.add_option("-d", "--dir", metavar='DIR', help="where put the source code")
    (options, args) = opt.parse_args()

    if options.dir: wd = options.dir
    else: wd = os.path.join(os.path.dirname(os.path.realpath(__file__)), os.getenv('WORKING_DIR', 'cache'))

    if not os.path.isdir(wd):
        opt.print_help()
        sys.exit("ERROR: the working directory %s does not exist" % wd)

    if not options.ver or not options.pkg:
        opt.print_help()
        sys.exit("ERROR: you need to give me a package and a version to download")

    print "The source code is in %s" % dget(options.pkg,options.ver,wd)