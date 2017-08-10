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

import sys
from os.path import dirname,join, abspath
from json import dump

TESTS = dirname(abspath(__file__))
REMOTE_FILES = join(TESTS,"remote_files")

save_path = sys.path
sys.path.insert(0, dirname(TESTS))
import remote_api
sys.path = save_path

cve = remote_api.CVE("CVE-2017-8401")

with open(join(REMOTE_FILES, "CVE-2017-8401.cve"),'w') as outfile:
    dump(cve.json, outfile)

patches = cve.patches
with open(join(REMOTE_FILES, "CVE-2017-8401.patches"), 'w') as outfile:
    dump([patches[0].json], outfile)

hunks= patches[0].hunks
with open(join(REMOTE_FILES, "CVE-2017-8401.hunk"), 'w') as outfile:
    dump([hunks[0].json], outfile)
