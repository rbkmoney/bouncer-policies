#! /usr/bin/env python3

import sys
import shlex
import subprocess
import json


class Bcolors:
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'


def print_coverage_info(fileName, coverage, threshold):
    if coverage < threshold:
        print(f"{fileName} {Bcolors.FAIL} {coverage}% FAIL {Bcolors.ENDC}")
    else:
        print(f"{fileName} {Bcolors.OKGREEN} {coverage}% OK {Bcolors.ENDC}")


def main(*argv):
    if len(argv) < 3:
        print("You failed to provide test coverage command.")
        sys.exit(1)

    print(f"{Bcolors.OKCYAN}TESTS COVERAGE: {Bcolors.ENDC}")

    test_coverage_command = shlex.split(str(argv[1]))
    threshold = int(argv[2])

    result = subprocess.check_output(test_coverage_command)
    resultJson = json.loads(result)

    files = resultJson["files"]
    notCovered = False

    for file in files.keys():
        coverage = files[file]["coverage"] if "coverage" in files[file] else 0
        if coverage < threshold:
            notCovered = True
        print_coverage_info(file, coverage, threshold)

    print(f"{Bcolors.OKCYAN}-----{Bcolors.ENDC}")
    fullCoverage = resultJson["coverage"]
    print_coverage_info(
        f"{Bcolors.BOLD}SUMMARY{Bcolors.ENDC}",
        fullCoverage,
        threshold
    )

    if notCovered:
        sys.exit(1)


if __name__ == '__main__':
    main(*sys.argv)
