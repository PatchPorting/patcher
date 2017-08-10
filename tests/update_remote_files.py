#!/usr/bin/env python

'''
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
'''

from os.path import dirname, abspath, join
import sys
from json import dumps

TESTS = dirname(abspath(__file__))
REMOTE_FILES = join(TESTS, "remote_files")
PKGS = join(TESTS, "pkgs")

save_path = sys.path
sys.path.insert(0, dirname(TESTS))
from remote_api import Remote,CVE
sys.path = save_path

cve = CVE("CVE-2016-9427")
files = {
    "CVE-2016-9427.cves": {"where":{"name": cve.name}, "path":'cves'},
    "CVE-2016-9427.cve": {"path":"cves/%s" % cve.id},
    "CVE-2016-9427.patchsets": {"path":"cves/%s/patchsets" % cve.id},
    "CVE-2016-9427.patches": {"path":"patchsets/%s/patches" % cve.patchsets[0].id},
    "CVE-2016-9427.hunks": {"path":"patches/%s/hunks" % cve.patchsets[0].patches[0].id},
    "CVE-2016-9427.hunk": {"path": "hunks/%s" % cve.patchsets[0].patches[0].hunks[0].id},
    "CVE-2016-9427.waitings": {"where":{"cveName": cve.name, "status":"waiting"},"limit": 1, "path": "builds"},
}

remote = Remote()

def cleanIds(l):
    for j in l:
        for k in j.keys():
            if k == 'id' or k[-2:] == 'Id': j[k] = '<removed>'
            if isinstance(j[k], list): cleanIds(j[k])

if __name__ == '__main__':
    for file,args in files.iteritems():
        json = remote._requestGET(**args)

        # Clean ids, since they change in every deploy
        if not isinstance(json, list): tmp = [json]
        else:                          tmp = json

        cleanIds(tmp)

        print file
        pretty = dumps(json, ensure_ascii=False, sort_keys=True, indent=2, separators=(',', ': '))
        with open(join(REMOTE_FILES, file), "w") as _file:
            _file.write(pretty)
