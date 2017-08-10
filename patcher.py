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
__author__ = "Luciano Bello <luciano.bello@ibm.com>"
__version__ = "0.0.1"

from dget import dget
from tempfile import mkdtemp
import os
from shutil import copytree,rmtree
from json import load
from copy import copy
from remote_api import Hunk, Build
from lib import groupByCVE, runinDIR, file2str, build
from capturing import Capturing
from datetime import datetime
from traceback import format_exc

with open(os.path.join(os.path.dirname(os.path.realpath(__file__)),"default-conf.json")) as conf_file:
    DEFAULTCONFjson = load(conf_file)

debug=False

def startLog(build=None):
    log = Capturing()
    if debug:
        print '>'*10
    else:
        log.build = build
        log.__enter__()
    return log

outLog = None

def readHunk(hunk):
    if "data" in hunk: return hunk["data"]
    if "file" in hunk:
        with open(hunk["file"], 'r') as hunkfile: # TODO This path might be usergenerated. Check path for security reasons.
            data = hunkfile.read().replace('\n', '')
        return data
    if "id" in hunk:
        h=Hunk(id=hunk["id"])
        return h.data


def createQuiltPatch(conf, hunks, quiltpatchname, dist):
    from patch_hunk import adapt

    #if not hunks:
    #    conf["status"] = "finished"
    #    return [conf]
    hunkConf = hunks.pop(0)
    wd = "%s-wd" % (conf['dir'])
    copytree(conf['dir'],wd)
    resultsd = "%s-results" % (conf['dir'])
    os.makedirs(resultsd)

    results = adapt(hunkConf.hunk.data, wd, hunkConf.setup.content, resultsd, debuglevel='debug')
    rmtree(wd)

    if results.status != "generated":
        conf["status"]  = "failed"
        conf["type"]    = "apply"
        conf["details"] = results.status
        updateResult(conf)
        return []

    conf['status'] = 'done'
    conf['heuristic'] = results.heuristic
    conf["children"]= [ "%s.%d" % (conf["id"],i) for i in range(len(results.genPatch))]

    queue = []
    for no,patchfile in enumerate(results.genPatch):
        child = {}
        child["id"] = "%s.%d" % (conf["id"],no)
        child['dir']= "%s.%d" % (conf['dir'],no)
        copytree(conf['dir'], child['dir'])
        runinDIR(["quilt", "fold"], child['dir'], stdin=file2str(patchfile))
        runinDIR(["quilt", "refresh"], child['dir'])
        child["status"] = "applied"
        with open(os.path.join(child['dir'],"debian","patches",quiltpatchname), 'r') as p:
            child["patch"] = p.read()
        queue += [child]
    conf["type"]="apply"
    if conf.has_key('patch'): del conf['patch']
    conf["hunkId"] = hunkConf.hunk.id
    updateResult(conf)

    if len(hunks) == 0: return queue #the queue contains just leafs

    if hunkConf.build: # in case the build is forced for this hunk
            for child in queue:
                buildPkg(child,dist)

    ret = []
    for child in queue:
        if child["status"] == "failed":ret += [child]
        else: ret += createQuiltPatch(child, copy(hunks), quiltpatchname, dist)

    rmtree(resultsd)
    return ret


def generatePatchName(name,path,count=0):
    if count == 0:
        patchName = "%s.patch" % name
    else:
        patchName = "%s_%i.patch" % (name,count)
    if not os.path.isfile(os.path.join(path,"debian","patches",patchName)):
        return patchName
    else:
        count +=1
        return generatePatchName(name,path,count)


def buildPkg(c,dist):
    b = build(c['dir'], dist)
    c['type'] = "build"
    if   b == 0: c['status'] = "done" #built!
    elif b == 1: c['status'] = "failed" #build failed
    else:        c['status'] = "build skipped (%i)" % b
    updateResult(c)


def updateBuildStatus(build, newStatus):
    if build.id == '<removed>': return None #Ignore, because I am running with a local file, not with a server
    build.updateStatus(newStatus)

def updateResult(result):
    global outLog

    result["date"] = datetime.utcnow().isoformat()
    result["log"] = []

    if debug:
        print 'UPDATE:', result
        print '<'*10
    else:
        outLog.__exit__()
        result["log"]= outLog
        outLog.build.updateResults(result)
    outLog = startLog(outLog.build)

def run(buildConfig, srcDir=None):
    global outLog
    outLog = startLog(buildConfig)

    updateBuildStatus(buildConfig,"in progress")
    buildConfig.updateStarted(datetime.utcnow().isoformat())

    initialStatus = "done"
    tmpDir = None
    if srcDir:
        ORIGSRC = srcDir
    else:
        tmpDir = mkdtemp(dir=os.path.join(os.path.dirname(os.path.realpath(__file__)), 'cache'))
        pkg = dget(buildConfig.pkgName, buildConfig.pkgVersion, tmpDir)
        if not pkg:
            print "Error retriving %s (%s). Aborting." % (buildConfig.pkgName, buildConfig.pkgVersion)
            initialStatus = "error"
            pkg = '<None>'

        ORIGSRC = os.path.join(tmpDir, pkg)

    print "Source %s (%s) in %s/" % (buildConfig.pkgName, buildConfig.pkgVersion, ORIGSRC)

    #There is a single root
    SRCs2apply=[{"dir":ORIGSRC,"id":"0"}]

    # Group hunks by CVE
    #[{ name: str, hunks: []}
    # ... ]
    try:
        CVE = groupByCVE(buildConfig.hunks)
    except:
        initialStatus="error"
        print format_exc()

    updateResult({"type":"initial","status":initialStatus, "id":"0"})
    if initialStatus == "error":
        return None

    leafs = []
    for cve in CVE:

        print "Adapting a patch for %s" % cve["name"]
        for SRC2apply in SRCs2apply:
            quiltname = generatePatchName(cve["name"],SRC2apply["dir"])

            d = "%s-%s" % (SRC2apply['dir'],cve['name'])
            copytree(SRC2apply['dir'], d)
            SRC2apply['dir'] = d

            runinDIR(["quilt", "new", quiltname], SRC2apply["dir"])
            leafs = createQuiltPatch(SRC2apply, cve["hunks"], quiltname, buildConfig.dist)

            # After a quilt patch, build them all!
            for leaf in leafs:
                buildPkg(leaf,buildConfig.dist)

        leafs = [leaf for leaf in leafs if leaf['status'] != 'failed'] #filters out when a leaf is failed
        SRCs2apply+=leafs
    if len(leafs) == 0:
        updateBuildStatus(buildConfig, "no solution")
    elif len(leafs) == 1:
        updateBuildStatus(buildConfig, "single solution")
    else:
        updateBuildStatus(buildConfig, "multiple solution")

    if tmpDir: rmtree(tmpDir)

def fetch(rawfilter):
    global outLog
    where = {}
    for rf in rawfilter:
        k,v = rf.split("=",1)
        if [v[0], v[-1]] == ['[', ']']:
            v = v[1:-1]
            v = v.split(',')
        where[k] = v

    while True:
        build = Build(where=where)
        try:
            run(build)
        except Exception, e:
            updateBuildStatus(build, "error")
            import traceback
            outLog.__exit__()
            print outLog
            traceback.print_exc()
            raise e

def main():
    from optparse import OptionParser
    from os.path import exists, isfile
    from json import load

    opt = OptionParser(usage="%prog [options]",
                       version="patcher %s" % __version__)
    opt.add_option("-f","--fetch", action="store_true", dest="fetch", help="Fetch from the waiting queue. The rest of the argments are used as filters (eg. pkgName=program pkgVersion=1.1 cveName=CVE-0000-1234)")
    opt.add_option("-d", "--debug", action="store_true", dest="debug",
                   help="Do not capture the output, useful for debugging")
    opt.add_option("-c", "--config", dest='conf', metavar='CONF_FILE.json',
                   help="specify the build configuration file")
    opt.add_option("-s", "--sourcedir", dest='srcDir', metavar='DIR',
                   help="Instead of dgetting the source code, get it from here. Useful for debugging.")
    (options, args) = opt.parse_args()


    if options.debug:
        global debug
        debug = True

    if options.fetch:
        fetch(args)
    else:
        # conf file existance check
        if not exists(options.conf) or not isfile(options.conf):
            import sys
            sys.exit("conf JSON file does not exist - %s" % options.conf)
        with open(options.conf) as conf_file:
            buildConfig = Build(load(conf_file))

        run(buildConfig, srcDir=options.srcDir)

if __name__ == "__main__":
    main()
