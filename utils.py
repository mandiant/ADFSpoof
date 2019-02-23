import random
import string
import sys


def random_string():
    return '_' + ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))


def new_guid(stream):
    guid = []
    zero = stream[0]
    one = stream[1]
    two = stream[2]
    three = stream[3]
    four = stream[4]
    five = stream[5]
    six = stream[6]
    seven = stream[7]
    guid.append(three << 24 | two << 16 | one << 8 | zero)
    guid.append(five << 8 | four)
    guid.append(seven << 8 | six)
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
    return guid_parts[0][6:] + guid_parts[0][4:6] + guid_parts[0][2:4] + guid_parts[0][0:2] + guid_parts[1][2:] + guid_parts[1][0:2] + guid_parts[2][2:] + guid_parts[2][0:2] + guid_parts[3] + guid_parts[4]


def die():
    sys.exit()
