#! /usr/bin/env python3

import sys
import shlex
import subprocess
import json


class Bcolors:
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    DIM = '\033[90m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'


def print_coverage_info(fileName, coverage, threshold, bold=False):
    if bold:
        fileNamePart = f"{Bcolors.BOLD}{fileName:<70}{Bcolors.ENDC}"
    else:
        fileNamePart = f"{fileName:<70}"
    if coverage < threshold:
        print(f"{fileNamePart}{Bcolors.FAIL}{coverage:>5.1f}% FAIL{Bcolors.ENDC}")
    else:
        print(f"{fileNamePart}{Bcolors.OKGREEN}{coverage:>5.1f}% OK{Bcolors.ENDC}")


def print_line_hilight(lineNum, line, color):
    stripped = line.strip('\n')
    print(f"{lineNum:>4} {color}{stripped}{Bcolors.ENDC}")
    return lineNum + 1

def print_coverage_details(fileName, notCoveredSegments):
    # How many lines to print before any segment, at most?
    ctxLinesBefore = 2
    # How many lines to print after any segment, at most?
    ctxLinesAfter = 2
    with open(fileName) as fd:
        lineNum = 1
        segEndLast = None
        for seg in notCoveredSegments:
            segStart = seg["start"]["row"]
            segEnd = seg["end"]["row"]
            # Printing "after" context of previous segment, if any.
            while segEndLast and lineNum <= segEndLast + ctxLinesAfter and lineNum < segStart:
                lineNum = print_line_hilight(lineNum, fd.readline(), Bcolors.DIM)
            # Skipping unrelated lines.
            while lineNum < segStart - ctxLinesBefore:
                fd.readline()
                lineNum += 1
            # Printing "before" context of current segment.
            while lineNum < segStart:
                lineNum = print_line_hilight(lineNum, fd.readline(), Bcolors.DIM)
            # Printing segment itself.
            while lineNum <= segEnd:
                lineNum = print_line_hilight(lineNum, fd.readline(), Bcolors.FAIL)
            segEndLast = segEnd
        # Printing "after" context of last segment, if any.
        while segEndLast and lineNum <= segEndLast + ctxLinesAfter:
            lineNum = print_line_hilight(lineNum, fd.readline(), Bcolors.DIM)


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
        print_coverage_info(file, coverage, threshold)
        if coverage < threshold:
            notCovered = True
            print_coverage_details(file[1:], files[file]["not_covered"])

    print(f"{Bcolors.OKCYAN}-----{Bcolors.ENDC}")
    fullCoverage = resultJson["coverage"]
    print_coverage_info(
        "SUMMARY",
        fullCoverage,
        threshold,
        bold=True
    )

    if notCovered:
        sys.exit(1)


if __name__ == '__main__':
    main(*sys.argv)
