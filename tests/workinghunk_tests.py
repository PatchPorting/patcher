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

from os.path import dirname, abspath, join, relpath
import unittest
import sys
from json import load
import shutil
from os import listdir, unlink

TESTS = dirname(abspath(__file__))
PKGS = join(TESTS, "pkgs")

# import code to test from parent directory
save_path = sys.path
sys.path.insert(0, dirname(TESTS))
import patch_hunk

sys.path = save_path


def get_file_content(filename):
    with open(filename, 'rb') as f:
        return f.read()


# ----------------------------------------------------------------------------
class TestPatchHunk(unittest.TestCase):
    def setUp(self):
        self.maxDiff = None
        self.wd = join(PKGS, "%s.working" % self.pkgdir)
        self.results = join(PKGS, "results")
        self.expected = join(PKGS, "expected")
        shutil.rmtree(self.wd, ignore_errors=True)
        shutil.copytree(join(PKGS, self.pkgdir), self.wd, ignore=shutil.ignore_patterns('.pc'))
        with open(join(TESTS, "..", "default-conf.json")) as conf_file:
            self.configjson = load(conf_file)

    def tearDown(self):
        shutil.rmtree(self.wd)
        for the_file in listdir(self.results):
            if not "patch" in the_file: continue
            unlink(join(self.results, the_file))

    def patch2test(self, tFile):
        with open(join(PKGS, "hunks", "%s.patch" % join(self.pkgdir,tFile))) as patch_file:
            patch_str = patch_file.read()

        if self._resultForDoCleanups.showAll:
            debug = "debug"
        else:
            debug = None

        r = patch_hunk.adapt(patch_str, self.wd, self.configjson, self.results, debug)
        self.assertIsNotNone(r)
        self.assertEqual(r.status, "generated")
        self.assertEqual(self.noResults,len(r.genPatch))
        for result in r.genPatch:
            expected = join(self.expected, self.pkgdir, tFile, dirname(tFile),relpath(result,self.results))
            self.assertMultiLineEqual(get_file_content(result), get_file_content(expected))


# ----------------------------------------------------------------------------

def test_generator(tFile,noResults):
    def test(self):
        self.noResults=noResults
        self.patch2test(tFile)
    return test


tests = [
    { "pkgdir": "libgc-7.2d",
      "patches": [
          { "name": "typd_mlc.c.0",
            "noResults": 3
            },
          {
           "name": "typd_mlc.c.1",
           "noResults": 1
          },
          {"name": "allchblk.c.0",
           "noResults": 1
          },
          {"name": "allchblk.c.1",
           "noResults": 1
          }
      ],
    },
    {
      "pkgdir": "botan1.10-1.10.8",
      "patches": [
          { "name": "log.txt.000",
            "noResults": 1
            },
          {
           "name": "parsing.cpp.000",
           "noResults": 1
          }
      ]
    }
]

allsuites = []
for tDir, tFiles in [ (i["pkgdir"],i["patches"]) for i in tests ]:
    testSuiteName = "Test_%s" % tDir.replace(".", ":")
    globals()[testSuiteName] = type(testSuiteName, (TestPatchHunk,), {"pkgdir": tDir})
    for tFile,noResults in [ (i["name"],i["noResults"]) for i in tFiles]:
        test_name = 'test_%s' % tFile.replace(".", ":")
        test = test_generator(tFile,noResults)
        setattr(globals()[testSuiteName], test_name, test)

if __name__ == '__main__':
    unittest.main()
