#!/usr/bin/env python3
#
# Deluge password generator
#
#   deluge.password.py <password> <salt>
#
#

import hashlib
import sys

password = sys.argv[1]
salt = sys.argv[2]

s = hashlib.sha1()
s.update(salt.encode('utf-8'))
s.update(password.encode('utf-8'))

print(s.hexdigest())

