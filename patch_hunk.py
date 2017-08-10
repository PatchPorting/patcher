#!/usr/bin/env python

"""
 Copyright (c) 2017 IBM Corp.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
"""

import logging
from os.path import isfile, isdir, dirname
from os import makedirs
import sys
import heuristics

__author__ = "Luciano Bello <luciano.bello@ibm.com>"
__version__ = "0.0.1"

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

streamhandler = logging.StreamHandler(stream=sys.stdout)
streamhandler.setLevel(logging.DEBUG)

logger.addHandler(streamhandler)

class RoundResult(object):
    def __init__(self):
        self.status = 'pending'
        self.patch = None

    def genResults(self,roundno,rDir):
        if self.status!="applicable": sys.exit("?!") #TODO
        if len(self.patch.items)!= 1: sys.exit("?!")  # TODO

        import subprocess

        self.roundno = roundno
        self.genPatch = []
        fname = self.patch.items[0].filenameo

        old = '%s/%s.orig' % (self.rootDir,fname)

        if not isfile(old):
            sys.exit('%s does not exist!' % old)

        if isfile('%s/%s' % (self.rootDir,fname)):
            new=['%s/%s' % (self.rootDir,fname)]
        else:
            from glob import glob
            new = filter(lambda x : x[-5:] != '.orig', glob('%s/%s.*' % (self.rootDir,fname)))

        for no,n in enumerate(new):
           self.genPatch += ["%s/%s.%d.patch" % (rDir, fname, no)]
           logger.info('Generated a patch based on %s: %s' % (n,self.genPatch[-1]))
           process = subprocess.Popen(['/usr/bin/diff', '-Naur', old, n],stdout=subprocess.PIPE)

           d = dirname(self.genPatch[-1])
           if not isdir(d):
               makedirs(d)

           with open(self.genPatch[-1], 'w') as new_patch:
               new_patch.write("--- a/%s\n" % fname)
               new_patch.write("+++ b/%s\n" % fname)
               process.stdout.next()
               process.stdout.next()
               for line in process.stdout:
                   new_patch.write(line)
        self.status = "generated"

    def setApplicable(self,d,p,n):
        self.status = "applicable"
        self.heuristic = n
        self.patch = p
        self.rootDir = d


def is_valid_heuristic(h):
    valid_heuristics = filter(lambda x: x[0]!='_' , dir(heuristics))
    if not h in valid_heuristics:
        logger.warning("The heuristic %s is not defined in %s and will be disabled." % (h,heuristics.__file__))
        return False
    return True

def items2dict(i):
    r={}
    for n,v in i:
       if v=='True' or v=='False':
           r[n]=bool(v)
       else:
           try:
               r[n] = int(v)
           except ValueError:
               r[n] = v
    return r

class Round(object):
    def __init__(self):
        self.strip = 0

def roundConf(h):
    m={}
    if h.has_key("options"):
        m.update(h["options"])
        m['name'] = '_'.join([h["heuristic"]]+[ "%s%s" % (i,j) for i,j in h["options"].iteritems()])
    else: m['name'] = h["heuristic"]
    m['apply'] = getattr(heuristics, h["heuristic"])
    m['result'] = RoundResult()
    RoundClass = type(str(h["heuristic"]), (Round,), m)
    return RoundClass()

def loadConf(jsonConf):
    ret = [ roundConf(h) for h in jsonConf if is_valid_heuristic(h["heuristic"]) ]
    return ret

def adapt(patch, dir, confjson, resultsDir='.', debuglevel=None):
    # patch: str
    # dir: str
    # confjson: json
    # resultsDir: str
    conf=loadConf(confjson)

    if debuglevel   == "debug"  :
        logger.setLevel(logging.DEBUG)
    elif debuglevel == "info"   :
        logger.setLevel(logging.INFO)
    elif debuglevel == "warning":
        logger.setLevel(logging.WARNING)
    else:
        logger.setLevel(logging.NOTSET)
    logger.addHandler(streamhandler)

    for count,round in enumerate(conf,1):
        logger.info(" = Running round %d (%s)" % (count,round.name))
        if round.apply(patch,dir):
            logger.info("Round %d (%s) applied!" % (count, round.name))
            round.result.genResults(count, resultsDir)
            return round.result
        logger.debug("Round %d (%s) failed!" % (count, round.name))
    else:
        logger.info("After %d rounds, it was not possible to apply the patch." % count)
    badResult = RoundResult()
    badResult.status = "unapplicable patch"
    return badResult

def main():
    from optparse import OptionParser
    from os.path import exists
    from json import load

    opt = OptionParser(usage="%prog [options] to_patch_directory/ unified.diff",
                       version="patch_hunk %s" % __version__)
    opt.add_option("-q", "--quiet", action="store_const", dest="verbosity",
                   const=0, help="print only warnings and errors", default=1)
    opt.add_option("-v", "--verbose", action="store_const", dest="verbosity",
                   const=2, help="be verbose")
    opt.add_option("--debug", action="store_true", dest="debugmode", help="debug mode")
    opt.add_option("-c", "--conf", dest='conf', metavar='CONF_FILE.json', default='default-conf.json',
                   help="specify the configuration file")
    (options, args) = opt.parse_args()

    verbosity_levels = {0: logging.WARNING, 1: logging.INFO, 2: logging.DEBUG}
    loglevel = verbosity_levels[options.verbosity]
    logformat = "%(message)s"
    logger.setLevel(loglevel)
    streamhandler.setFormatter(logging.Formatter(logformat))

    if not args or not len(args) == 2:
        opt.print_version()
        opt.print_help()
        sys.exit()

    dir_to_patch = args[0]
    patchfile = args[1]

    # patch existance check
    if not exists(patchfile) or not isfile(patchfile):
        sys.exit("patch file does not exist - %s" % patchfile)
    with open(patchfile) as patch_file:
        patch_str = patch_file.read()

    # directory existance check
    if not exists(dir_to_patch) or not isdir(dir_to_patch):
        sys.exit("source directory does not exist - %s" % dir_to_patch)

    # conf file existance check
    if not exists(options.conf) or not isfile(options.conf):
        sys.exit("conf JSON file does not exist - %s" % options.conf)
    with open(options.conf) as conf_file:
        config = load(conf_file)

    adapt(patch_str, dir_to_patch, config)

if __name__ == "__main__":
    main()
