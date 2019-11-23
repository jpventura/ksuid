#!/usr/bin/env python3

from collections import namedtuple
from datetime import datetime
from functools import reduce
from string import hexdigits

BASE_62 = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
BASE_OF = len(BASE_62)

TABLE_ENCODE = str.maketrans(dict(zip(
  range(len(BASE_62)),
  BASE_62
)))

# TABLE_DECODE = str.maketrans(dict(zip(
#   BASE_62,
#   map(str, range(len(BASE_62)))
# )))

TABLE_DECODE = dict(zip(
  BASE_62,
  range(len(BASE_62))
))

# TABLE_ENCODE = str.maketrans(dict(zip(map(str, range(len(BASE_62))), BASE_62)))

# TABLE_ENCODE = str.maketrans(dict(zip(
#   BASE_62,
#   range(len(BASE_62))
# )))




EPOCH_SHIFT = 14e8
KSUID_PAYLOAD = 0x00000000ffffffffffffffffffffffffffffffff









ID = '0ujzPyRiIAffKhBux4PvQdDqMHY'
RAW = 0x066A029C73FC1AA3B2446246D6E89FCD909E8FE8

BITS_PER_BYTE =  8
BYTES_PAYLOAD = 16
BYTES_KSUID = 20
BYTES_TIMESTAMP =  4

# KSUID_MAX = 0xffffffffffffffffffffffffffffffffffffffff

KSUID_MIN = 0x0
KSUID_MAX = 2**160 - 1
MAX_KSUID_ENCODED = 'aWgEPTl1tmebfsQzFP4bxwgy80V'

MAX_KSUID_ENCODED_LENGTH = len(MAX_KSUID_ENCODED)


def _ksuid_check(ksuid):
  if type(ksuid) != str:
    msg = 'expected ID of type str, not %s' % type(ksuid).__name__
    raise TypeError(msg)

  if len(ksuid) < MAX_KSUID_ENCODED_LENGTH:
    ksuid = '0'*(MAX_KSUID_ENCODED_LENGTH - len(ksuid)) + ksuid

  if ksuid >= MAX_KSUID_ENCODED:
    msg = 'ID above %s limit: %s' % (MAX_KSUID_ENCODED, ksuid)
    raise ValueError(msg)

  return ksuid

def decode(ksuid):
  formatted_ksuid = _ksuid_check(ksuid)

  def decimal(item):
    digit, exp = item
    return (BASE_OF**exp)*TABLE_DECODE[digit]
  
  raw = sum(map(decimal, zip(reversed(formatted_ksuid), range(BASE_OF))))

  return format(raw, '0>40x')

def isotime(id):
  moment = datetime.fromtimestamp(timestamp(id))
  return '%sZ' % moment.isoformat(timespec='milliseconds')

def payload(id):
  if (type(id) == str) and set(hexdigits).issuperset(id):
    return payload(int(id, base=16))

  if (type(id) == str) and set(BASE_62).issuperset(id):
    return payload(decode(id))

  if (type(id) == int) and (KSUID_MIN <= id <= KSUID_MAX):
    return format(id & KSUID_PAYLOAD, 'x')

  msg = 'expected id of type int or str, not %s' % type(id).__name__
  raise TypeError(msg)

def timestamp(id):
  if (type(id) == str) and set(hexdigits).issuperset(id):
    return timestamp(int(id, base=16))

  if (type(id) == str) and set(BASE_62).issuperset(id):
    return timestamp(decode(id))

  if (type(id) == int) and (KSUID_MIN <= id <= KSUID_MAX):
    return int((id >> 128) + EPOCH_SHIFT)

  msg = 'expected id of type int or str, not %s' % type(id).__name__
  raise TypeError(msg)

KSUID = namedtuple('KSUID', ['iso_datetime', 'payload', 'timestamp'])

def inspect(id):
  if (type(id) == str) and set(hexdigits).issuperset(id):
    return inspect(int(id, base=16))

  if (type(id) == str) and set(BASE_62).issuperset(id):
    return inspect(decode(id))

  if (type(id) == int) and (KSUID_MIN <= id <= KSUID_MAX):
    return KSUID(isotime(id), payload(id), timestamp(id))

  msg = 'expected id of type int or str, not %s' % type(id).__name__
  raise TypeError(msg)

def main():
  print(inspect(ID))

  # print(hex(int(RAW, base=16)))
  

  
  # timestamp = hex(decode(KSUID))[2:]
  # print(zulu_time(107610780))
  # assert hex(decode(KSUID)) == hex(int(RAW, base=16))


if __name__ == '__main__':
  main()
