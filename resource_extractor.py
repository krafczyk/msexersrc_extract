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

# Get offsets to tables
table_offsets = struct.unpack('<HHHHH', ne_header[0x22:0x2C])

seg_table_offset = table_offsets[0]
resource_table_offset = table_offsets[1]
resident_name_table_offset = table_offsets[2]
mod_ref_table_offset = table_offsets[3]
imp_name_table_offset = table_offsets[4]

# Get offset of resident name table
resident_name_table_offset = struct.unpack('<H', ne_header[0x26:0x28])[0]

# Seek to resource table
input_file.seek(ne_header_offset+resource_table_offset)

def read_byte():
    return struct.unpack('<B', input_file.read(0x1))[0]

def read_word():
    return struct.unpack('<H', input_file.read(0x2))[0]

def read_dword():
    return struct.unpack('<I', input_file.read(0x4))[0]

# Get alignment shift count
resource_alignment_shift_count = read_word()
resource_block_size = 1 << resource_alignment_shift_count;

print("Resource Alignment Shift Count: {}".format(resource_alignment_shift_count))
print("Resource Block Size: {}".format(resource_block_size))

class resource_table_entry(object):
    def __init__(self):
        bytebuf = input_file.read(12)
        self._offset , self._len, self._flagword, self._rid = struct.unpack('<HHHH', bytebuf[0x0:0x8])
        if (self._rid & 0x8000) == 0:
            current_offset = input_file.tell()
            input_file.seek(ne_header_offset+resource_table_offset+self._rid)
            length = read_byte()
            self._resource_name = input_file.read(length).decode('utf8')
            input_file.seek(current_offset)
        else:
            self._resource_name = "#{}".format(hex(self._rid & 0xFFF))
    def __str__(self):
        str_trans = "name: {} ".format(self._resource_name)
        if self._flagword & 0x10:
            str_trans += "moveable "
        if self._flagword & 0x20:
            str_trans += "shareable "
        if self._flagword & 0x40:
            str_trans += "preload "

        return str_trans

# Resource lists
resource_lists = {}

# Loop through table.
while True:
    # New table type
    type_raw = read_word()
    if type_raw == 0:
        break

    if (type_raw & 0x8000) == 0:
        print("ERROR! don't support non integer resource types!")
        cleanup()
        sys.exit(1)

    num_resources = read_word()

    # this if from semblance
    resloader = read_dword()
    if resloader != 0:
        print("WARNING! resloader is not zero")

    type_int = type_raw & 0xFFF

    resource_lists[type_int] = []

    print("Type is: {}".format(hex(type_int)))
    print("There are: {}".format(num_resources))

    r_i = 0
    while r_i < num_resources:
        r_i += 1
        resource_entry = resource_table_entry()
        resource_lists[type_int].append(resource_entry)
        print(resource_entry)
