What's this?
------------
This bunch of scripts run the **patcher** engine, a platform for porting security patches easily. Since it calls many Debian commands, it can only run in a Debian docker or enviroment. For the moment, it is written for Python 2. Help us porting it to Python 3!

Running the patcher
--------------------
With local configuration.
The file `/app/patcher/demo-config.json` contains a json `build` object, as you can get from [here](https://patchport-http.mybluemix.net/api/v0/builds/5975dad2504796002ecf1d1d):

```
./patcher.py -c /app/patcher/demo-config.json
```

Remote fetching. It fetches the next *waiting* build from the server, using the connection token defined in the env `TOKEN`:

```
./patcher.py -f pkgName=botan1.10 dist=jessie 
```


Running dget.py
--------------
Downloads the Debian source of a particular package in a particular version.
```
./dget.py -p libgc -v 1:7.4.2-8 -d /app/patcher/cache/
```

Adapting a hunk
------------
```
./patch_hunk.py cache/CVE-2016-9427/gc-7.2 cache/CVE-2016-9427/typd_mlc.c.0.patch --debug -c config.json
```