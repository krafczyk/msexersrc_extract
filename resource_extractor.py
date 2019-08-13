import argparse
import os
import sys

parser = argparse.ArgumentParser()
parser.add_argument("infile", help="Input Executable", required=True, type=str)

args = parser.parse_args()

infile_path = args.infile

cleanup_actions = []

def cleanup():
    for action in cleanup_actions:
        action()

# Check whether input file exists
if not os.path.exists(infile_path):
    print("Input executable must exist!")
    sys.exit(1)

# Open input file
input_file = open(infile_path, mode='rb')

# Verify that the file was opened properly
if input_file is None:
    print("There was a problem opening the file {}", infile_path)
    sys.exit(1)

# Method to close input file
def close_input():
    input_file.close()

# Add the method to the cleanup methods
cleanup_actions.append(close_input)

dos_header = input_file.read(0x3C)
