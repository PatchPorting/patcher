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

from remote_api import Hunk, Setup
import os
import subprocess

class HunkConf(object):
    def __init__(self,hunkConf,setup):
        self.hunk = Hunk(id=hunkConf["id"])
        self.build = "build" in hunkConf.keys() and hunkConf["build"]
        self.setup = setup

    @property
    def cve(self):
        return self.hunk.cve.name

def file2str(filename):
    with open(filename, 'r') as p:
        r = p.read()
    return r

def runinDIR(command,DIR,stdin=None,env=None):
    prevdir = os.getcwd()
    os.chdir(DIR)
    proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE, env=env)
    (out, err) = proc.communicate(input=stdin)
    ret = proc.returncode
    print '=' * 5
    print "Running '%s' in '%s' (return code %s)" % (' '.join(command), os.path.basename(DIR), ret)
    if out:
        print '-' * 5, "stdout"
        print truncate(out)
    if err:
        print '-' * 5, "stderr"
        print truncate(err)
    print '=' * 5
    os.chdir(prevdir)
    return ret

def truncate(string):
    '''truncate strings'''
    LENGTH = 40000
    if len(string) > LENGTH:
        string = "(truncated to %d chars)\r\n" % LENGTH + string[-LENGTH:]
    return string

def build(dir,dist):
    print "building %s in a %s env" % (os.path.basename(dir),dist)
    env = os.environ.copy()
    env["DIST"] = dist
    return runinDIR(["pdebuild","--use-pdebuild-internal"], dir, env=env)

def groupByCVE(hunks):
    CVE = []
    setupcache = {} #To avoid each HunkConf to create their own Setup object

    for hunk in hunks:
        setupId = hunk["setupId"]
        if not setupId in setupcache.keys(): setupcache[setupId] = Setup(id=setupId)

        h = HunkConf(hunk, setupcache[hunk["setupId"]])

        if CVE[-1:] and CVE[-1]['name'] == h.cve:
            CVE[-1]['hunks'].append(h)
        else:
            hc = { 'name': h.cve, 'hunks': [h]}
            CVE.append(hc)

    return CVE
