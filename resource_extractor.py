import argparse
import os
import sys
import struct

parser = argparse.ArgumentParser()
parser.add_argument("infile", help="Input Executable", type=str)

args = parser.parse_args()

infile_path = args.infile

cleanup_actions = []

def cleanup():
    for action in cleanup_actions:
        action()

# Check whether input file exists
if not os.path.exists(infile_path):
    print("Input executable must exist!")
    cleanup()
    sys.exit(1)

# Open input file
input_file = open(infile_path, mode='rb')

# Verify that the file was opened properly
if input_file is None:
    print("There was a problem opening the file {}", infile_path)
    cleanup()
    sys.exit(1)

# Method to close input file
def close_input():
    input_file.close()

# Add the method to the cleanup methods
cleanup_actions.append(close_input)

# Read the dos header
dos_header = input_file.read(0x40)

# Check for correct DOS header
if dos_header[0x0:0x2].decode('utf8') != 'MZ':
    print("This is not a valid MZ executable!")
    cleanup()
    sys.exit(1)

# Fetch the new exectuable offset
ne_header_offset = struct.unpack('<i', dos_header[0x3C:0x40])[0]


# Seek to the new executable header
input_file.seek(ne_header_offset)

# Get the NE EXE header
ne_header = input_file.read(0x40)

# Check that this is a valid NE exe
if ne_header[0x0:0x2].decode('utf8') != 'NE':
    print("This is not a valid NE executable!")
    cleanup()
    sys.exit(1)
