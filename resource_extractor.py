import argparse
import os

parser = argparse.ArgumentParser()
parser.add_argument("infile", help="Input Executable", required=True, type=str)

args = parser.parse_args()


