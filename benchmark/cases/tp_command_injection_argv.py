"""Not every source is HTTP: argv is one too."""

import subprocess
import sys


def main():
    target = sys.argv[1]
    subprocess.check_output("nslookup " + target, shell=True)


if __name__ == "__main__":
    main()
