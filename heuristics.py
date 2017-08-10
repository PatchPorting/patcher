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

def Classical(self,patchfile,target):
    #TODO
    return False

def Offset(self,patchfile,target):
    from python_patch import patch

    p = patch.fromstring(patchfile)
    if p.apply(root=target, allowoffset=True, keep_orig=True):
        self.result.setApplicable(target, p, self.name)
        return True
    return False


def IgnoreFilename(self,patchfile,target):
	# TODO
	return False

def Fuzz(self,patchfile,target):
    from python_patch import patch

    p=patch.fromstring(patchfile)
    fromTop = 0 if not "fromTop" in dir(self) else self.fromTop
    fromBottom = 0 if not "fromBottom" in dir(self) else self.fromBottom
    if p.apply(root=target, allowoffset=True, keep_orig=True, fuzz_fromTop=fromTop, fuzz_fromBottom=fromBottom):
       self.result.setApplicable(target,p,self.name)
       return True
    return False

def FuzzIgnoreFilename(self,patch,target):
	# TODO
	return False
