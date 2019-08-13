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
ne_header_offset = struct.unpack('<I', dos_header[0x3C:0x40])[0]


# Seek to the new executable header
input_file.seek(ne_header_offset)

# Get the NE EXE header
ne_header = input_file.read(0x40)

# Check that this is a valid NE exe
if ne_header[0x0:0x2].decode('utf8') != 'NE':
    print("This is not a valid NE executable!")
    cleanup()
    sys.exit(1)

# Get offset to resource table
resource_table_offset = struct.unpack('<H', ne_header[0x24:0x26])[0]

# Get offset of resident name table
resident_name_table_offset = struct.unpack('<H', ne_header[0x26:0x28])[0]

# Resource lists
resource_lists = {}

# Seek to resource table
current_offset = ne_header_offset+resource_table_offset
input_file.seek(current_offset)

def read_bytes(num):
    global current_offset
    bytebuf = input_file.read(num)
    current_offset += num
    return bytebuf

# Get alignment shift count
bytebuf = read_bytes(0x2)
resource_alignment_shift_count = struct.unpack('<H', bytebuf)[0]
resource_block_size = 1 << resource_alignment_shift_count;

print("Resource Alignment Shift Count: {}".format(resource_alignment_shift_count))
print("Resource Block Size: {}".format(resource_block_size))

print("current_offset: {}".format(current_offset))
print("resident_name_table_offset: {}".format(resident_name_table_offset+ne_header_offset))

# Loop through table.
while ((ne_header_offset+resident_name_table_offset) - current_offset) >= 20:
    # New table type
    bytebuf = read_bytes(0x8)
    type_raw = struct.unpack('<H', bytebuf[0x0:0x2])[0]
    num_resources = struct.unpack('<H', bytebuf[0x2:0x4])[0]
    if (type_raw & 0x8000) == 0:
        print("ERROR! don't support non integer resource types!")
        cleanup()
        sys.exit(1)
    type_int = type_raw & 0xFFF
    r_i = 0

    print("Type is: {}".format(hex(type_int)))

    print("Exit early!")
    sys.exit(0)


