#!/usr/bin/env python3
#
# Deluge hostlist id generator
#
#   deluge.addHost.py
#
#

import hashlib
import sys
import time

print(hashlib.sha1(str(time.time()).encode('utf-8')).hexdigest())

