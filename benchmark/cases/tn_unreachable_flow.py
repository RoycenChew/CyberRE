"""A genuine-looking flow in a function nothing can call.

Unreachable code is the most common reason a true-looking finding is not
one, which is why reachability is weighted as heavily as it is.
"""

import os


def _legacy_debug_handler(payload):
    os.system("echo " + payload)
