"""A value that looks like a parameter but is internal."""

import subprocess

DEFAULT_HOST = "localhost"


def check(host=DEFAULT_HOST):
    subprocess.run("ping -c 1 " + host, shell=True)


def main():
    check()
