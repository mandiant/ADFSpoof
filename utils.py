import random
import string
import sys
import base64


def random_string():
    return '_' + ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))


def new_guid(stream):
    guid = []
    guid.append(stream[3] << 24 | stream[2] << 16 | stream[1] << 8 | stream[0])
    guid.append(stream[5] << 8 | stream[4])
    guid.append(stream[7] << 8 | stream[6])
    guid.append(stream[8])
    guid.append(stream[9])
    guid.append(stream[10])
    guid.append(stream[11])
    guid.append(stream[12])
    guid.append(stream[13])
    guid.append(stream[14])
    guid.append(stream[15])
    return guid


def encode_object_guid(guid):
    guid = guid.replace('}', '').replace('{', '')
    guid_parts = guid.split('-')
    hex_string = guid_parts[0][6:] + guid_parts[0][4:6] + guid_parts[0][2:4] + guid_parts[0][0:2] + guid_parts[1][2:] + guid_parts[1][0:2] + guid_parts[2][2:] + guid_parts[2][0:2] + guid_parts[3] + guid_parts[4]
    hex_array = bytearray.fromhex(hex_string)
    immutable_id = base64.b64encode(hex_array)
    return immutable_id


def die():
    sys.exit()


def print_intro():

    print('    ___    ____  ___________                   ____')
    print('   /   |  / __ \/ ____/ ___/____  ____  ____  / __/')
    print('  / /| | / / / / /_   \__ \/ __ \/ __ \/ __ \/ /_  ')
    print(' / ___ |/ /_/ / __/  ___/ / /_/ / /_/ / /_/ / __/  ')
    print('/_/  |_/_____/_/    /____/ .___/\____/\____/_/     ')
    print('                        /_/                        \n')
    print('A tool to for AD FS security tokens')
    print('Created by @doughsec\n')
