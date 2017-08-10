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

import requests
import json
from os import getenv

HOST= 'patchport-http.mybluemix.net'
VER = 'v0'
TOKEN = getenv("TOKEN")

if not TOKEN:
    print ("Set env variable TOKEN with the access token if you want to access the remote API.")

class Remote(object):
    def __init__(self):
        self.APIurl   = "https://%s/api/%s" % (HOST, VER)
        self.token = TOKEN

    def _requestPOST(self, path, data={}):
        headers = {'content-type': 'application/json'}
        u = "%s/%s?access_token=%s" % (self.APIurl, path, self.token)
        r = requests.post(u,data=data,headers=headers)
        if not r.status_code == 200:
            raise Exception('Error %d: %s\n%s' % (r.status_code,r.reason,u))
        return r.json()

    def _requestPATCH(self, path, data={}):
        headers = {'content-type': 'application/json'}
        u = "%s/%s?access_token=%s" % (self.APIurl, path, self.token)
        r = requests.patch(u,data=data,headers=headers)
        if not r.status_code == 200:
            raise Exception('Error %d: %s\n%s' % (r.status_code,r.reason,u))
        return r.json()

    def _requestDELETE(self, path):
        u = "%s/%s?access_token=%s" % (self.APIurl, path, self.token)
        r = requests.delete(u)
        if not r.status_code == 200:
            raise Exception('Error %d: %s\n%s' % (r.status_code,r.reason,u))
        return r.json()

    def _requestGET(self, path, where=None, order=None, limit=None):
        filter = {}

        if where:
            filter["where"] = where

        if order:
            filter["order"] = order

        if limit:
            filter["limit"] = limit

        u = "%s/%s?filter=%s&access_token=%s" % (self.APIurl, path, json.dumps(filter), self.token)
        r = requests.get(u)
        if not r.status_code == 200:
            raise Exception('Error %d: %s\n%s' % (r.status_code,r.reason,u))
        return r.json()

    def _findById(self,path, id):

        # Is it a local file (instead of a remote id). This is just for debugging and should be removed TODO
        if len(id) > 1 and id[0] == '<' and id[-1] == '>' and id != "<removed>":
            with open(id[1:-1]) as data_file:
                return  json.load(data_file)

        return self._requestGET(path=path % id)
        #TODO catch empty

    def reprJSON(self):
        r = {}
        for k, v in self.__dict__.iteritems():
            if k in self._postableFields: r[k] = v
        return r


class CVE(Remote):
    def __init__(self, name=None, id=None):
        Remote.__init__(self)
        if id:   cve = self._findById("cves/%s", id)
        elif name: cve = self._findByName(name)
        else: raise Exception('You have to give something to construct this CVE')
        self.__dict__.update(cve)

    def _findByName(self,name):
        cves = self._requestGET(where={"name": name}, path='cves')
        if len(cves) == 1:
            return cves[0]
        elif len(cves) == 0:
            raise Exception('CVE id not found: %s' % name)
        else:
            raise Exception('Multiple CVEs match %s' % name)

    def __getattr__(self, item):
        if item is "patchsets":
            patchsets = self._requestGET(path="cves/%s/patchsets" % self.id)
            self.patchsets = [Patchsets(json=patchset) for patchset in patchsets]
            return self.patchsets
        else:
            raise AttributeError(item)


class Patchsets(Remote):
    def __init__(self,json={}):
        Remote.__init__(self)
        self.__dict__.update(json)

    def __getattr__(self, item):
        if item is "patches":
            patches = self._requestGET(path="patchsets/%s/patches" % self.id)
            self.patches = [Hunk(json=patch) for patch in patches]
            return self.patches
        else:
            raise AttributeError(item)

class Patch(Remote):
    def __init__(self,json={}):
        Remote.__init__(self)
        self.__dict__.update(json)

    def __getattr__(self, item):
        if item is "hunks":
            hunks = self._requestGET(path="patches/%s/hunks" % self.id)
            self.hunks= [Hunk(json=patch) for patch in hunks]
            return self.hunks
        else:
            raise AttributeError(item)

class Hunk(Remote):
    _postableFields = [
        'cveId',
        'data',
        'fileName',
        'id',
        'patchId',
        'patchsetId'
        ]
    def __init__(self,json={},id=None):
        Remote.__init__(self)
        if id: json=self._findById("hunks/%s", id)
        self.__dict__.update(json)

    def __getattr__(self, item):
        if item is "hunks":
            hunks = self._requestGET(path="patches/%s/hunks" % self.id)
            self.hunks= [Hunk(json=patch) for patch in hunks]
        elif item is "cve":
            self.cve = CVE(id=self.cveId)
        else:
            return self.__dict__[item]
        return getattr(self,item)

class Setup(Remote):
    def __init__(self,json={},id=None):
        Remote.__init__(self)
        if id: json=self._findById("setups/%s", id)
        self.name = json['name']
        self.content = json['content']
        self.id = json['id']

class Build(Remote):
    _postableFields = ['pkgName',
                      'pkgVersion',
                      'mode',
                      'status',
                      'dist',
                      'urgency',
                      'hunks',
                      'results',
                      'cveId',
                      'patchsetId',
                      'cveName',
                      'id']

    def __init__(self,json={},where=None, id=None):
        '''if empty, get the next waiting build.
        with where, it gives you the next waiting with that filter'''
        Remote.__init__(self)
        if id: json = self._findById("builds/%s",id)
        if not json: json = self._nextWaiting(where=where)
        if not json:
            from json import dumps
            raise Exception('No pending builds (filter: %s)' % dumps(where))
        self.__dict__.update(json)

    def _nextWaiting(self,json={},where={}):
        where["status"] = "waiting"
        result = self._requestGET(where=where, limit=1, order='timestamp ASC', path='builds')
        if len(result): return result[0]
        else: return None

    def updateResults(self,data):
        if not isinstance(data,list):
            data = [data]

        o = {'buildId':self.id, 'data': {}}
        for d in data:
            o['data'] = d
            self._requestPOST(path='results', data=json.dumps(o))
        # TODO update the object with the new data?

    def updateStatus(self, status):
        result = self._requestPATCH(path='builds/%s' % self.id,data=json.dumps({'status': status}))
        # TODO update the object with the new data?
        return result

    def updateStarted(self, now):
        result = self._requestPATCH(path='builds/%s' % self.id,data=json.dumps({'started': now}))
        return result

    def postme(self):
        data = json.dumps(self.reprJSON(), cls=ComplexEncoder)
        result = self._requestPOST(path='builds',data=data)
        return Build(result)

class RemoteEncoder(json.JSONEncoder):
    def default(self, o):
        r = {}
        if type(o) is str: return o
        for k,v in o.__dict__.iteritems():
            if k in o._postableFields: r[k] = json.dumps(v, cls=RemoteEncoder)
        return r

class ComplexEncoder(json.JSONEncoder):
    def default(self, obj):
        if hasattr(obj,'reprJSON'):
            return obj.reprJSON()
        else:
            return json.JSONEncoder.default(self, obj)

class Result(Remote):
    _postableFields =[
        'children',
        'deb',
        'debdiff',
        'hunkId',
        'id',
        'log',
        'results',
        'status',
        'type']

    def __init__(self, json={}):
        Remote.__init__(self)
        self.__dict__.update(json)

class Results(list):
    def __init__(self, results=[],buildId=None):
        list.__init__(self)
        if buildId:
            r = Remote()
            results = r._requestGET(where={"buildId": buildId}, path='results')
        for result in results:
            self.append(Result(json=result))