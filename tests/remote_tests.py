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
from os import getenv
import unittest
import sys
from json import load
from mock import patch, MagicMock, PropertyMock

TESTS = dirname(abspath(__file__))
REMOTE_FILES = join(TESTS, "remote_files")
PKGS = join(TESTS, "pkgs")

# import code to test from parent directory
save_path = sys.path
sys.path.insert(0, dirname(TESTS))
import remote_api

sys.path = save_path

TOKEN = getenv("TOKEN")
realserver = bool(TOKEN)

cveID = "CVE-2016-9427"

def fakeServer(mockfile):
    if realserver:
        def f(a):
            return a
        return f
    else:
        mock = MagicMock()
        with open(join(REMOTE_FILES, mockfile)) as data_file:
            j = load(data_file)
            type(mock.return_value).json = lambda x: j
        type(mock.return_value).status_code = PropertyMock(return_value=200)
        return patch('remote_api.requests.get', mock)

def _assertRemoteEqual(self,file,obj):
    with open(join(REMOTE_FILES, file)) as data_file:
        expecteds = load(data_file)

    if not isinstance(expecteds, list): expecteds = [expecteds]
    if not isinstance(obj, list): obj = [obj]
    self.assertRemoteEqualList(expecteds,obj)

def _assertRemoteEqualList(self,expecteds,givens):
    for i,expected in enumerate(expecteds):
        for k in expected.keys():
            if k == 'id' or k[-2:] == 'Id': continue
            if isinstance(expected[k], list): self.assertRemoteEqualList(expected[k],getattr(givens[i],k))
            elif isinstance(givens[i],dict):
                self.assertEqual(expected[k], givens[i][k])
            else:
                self.assertEqual(expected[k], getattr(givens[i],k))

unittest.TestCase.assertRemoteEqual = _assertRemoteEqual
unittest.TestCase.assertRemoteEqualList = _assertRemoteEqualList

# ----------------------------------------------------------------------------

@fakeServer("%s.cves" % cveID)
def getCVE(cve):
    return remote_api.CVE(cve)

@fakeServer("%s.hunks" % cveID)
def getAHunkIdForThisCveId(cveId):
    r = remote_api.Remote()
    return r._requestGET("/cves/%s/hunks" %cveId,limit=1)[0]["id"]

class Test_CVE_2016_9427(unittest.TestCase):

    def setUp(self):
        self.cveID = cveID
        self.cve = getCVE(self.cveID)

    def test_CVE(self):
        self.assertIsNotNone(self.cve)
        self.assertEqual(self.cve.name, self.cveID)
        self.assertRemoteEqual("%s.cves" % self.cveID,[self.cve])

    @fakeServer("%s.patchsets" % cveID)
    def test_CVEpatchset(self):
        patchsets = self.cve.patchsets
        self.assertIsNotNone(patchsets)
        self.assertEqual(len(patchsets), 4)
        self.assertRemoteEqual("CVE-2016-9427.patchsets",patchsets)

    @fakeServer("%s.patches" % cveID)
    def test_CVEpatch(self):
        patches = self.cve.patchsets[0].patches
        self.assertIsNotNone(patches)
        self.assertEqual(len(patches), 4)
        self.assertRemoteEqual("%s.patches" % self.cveID, patches)

    @fakeServer("%s.hunks" % cveID)
    def test_CVEhunk(self):
        hunks = self.cve.patchsets[0].patches[0].hunks
        self.assertEqual(len(hunks), 2)
        self.assertRemoteEqual("%s.hunks" % self.cveID, hunks)

# ----------------------------------------------------------------------------

class Test_Hunk_CVE_2016_9427(unittest.TestCase):

    @fakeServer("%s.hunk" % cveID)
    def setUp(self):
        cve = getCVE(cveID)
        self.hunkId = getAHunkIdForThisCveId(cve.id)
        self.hunk = remote_api.Hunk(id=self.hunkId)

    @fakeServer("%s.hunk" % cveID)
    def test_hunkById(self):
        self.hunk = remote_api.Hunk(id=self.hunkId)
        self.assertIsNotNone(self.hunk)
        self.assertRemoteEqual("%s.hunk" % cveID, self.hunk)

    @fakeServer("%s.cve" % cveID)
    def test_cve(self):
        cve = self.hunk.cve
        self.assertIsNotNone(self.hunk)
        self.assertRemoteEqual("%s.cve" % cveID, cve)

# ----------------------------------------------------------------------------

class Test_Build_CVE_2016_9427(unittest.TestCase):

    @fakeServer("%s.waitings" % cveID)
    def setUp(self):
        self.build = remote_api.Build(where={"cveName":cveID})

    def test_buildConstructor(self):
        self.assertIsNotNone(self.build)
        self.assertRemoteEqual("%s.waitings" % cveID, self.build)

    @fakeServer("emptyArray")
    def test_emptyBuild(self):
        with self.assertRaises(Exception) as context:
            build = remote_api.Build(where={"cveName": "CVE-0000-0000", "dist": "jessie"})
        self.assertTrue('No pending builds' in context.exception.message)

    def test_updateStatus(self):
        result = self.build.updateStatus("pending")
        self.assertEqual(result['status'],'pending')

if __name__ == '__main__':
    unittest.main()
