#!/bin/sh
python2 -m unittest discover --start-directory="." --pattern=*_tests.py  $*
