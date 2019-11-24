#!/usr/bin/env python3

from collections import namedtuple
from datetime import datetime
from string import hexdigits
from typing import NamedTuple

import json
import uuid

BASE_62 = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
BASE_OF = 62

TABLE_ENCODE = str.maketrans(dict(zip(
  range(BASE_OF),
  BASE_62
)))

TABLE_DECODE = dict(zip(
  BASE_62,
  range(BASE_OF)
))

KSUID_EPOCH_ISO8601 = '2014-05-13T16:53:20.000Z'
KSUID_EPOCH_TIMESTAMP = 14e8
KSUID_PAYLOAD = 0x00000000ffffffffffffffffffffffffffffffff









ID = '0ujzPyRiIAffKhBux4PvQdDqMHY'
RAW = 0x066A029C73FC1AA3B2446246D6E89FCD909E8FE8

BITS_PER_BYTE =  8
BYTES_PAYLOAD = 16
BYTES_KSUID = 20
BYTES_TIMESTAMP =  4

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
    return int((id >> 128) + KSUID_EPOCH_TIMESTAMP)

  msg = 'expected id of type int or str, not %s' % type(id).__name__
  raise TypeError(msg)

class KSUID(NamedTuple):
  """K-Sorted ID"""
  created_at : str = KSUID_EPOCH_ISO8601
  payload    : int = 0
  timestamp  : int = 0

  def __str__(self):
    return json.dumps({
      '_id': str(uuid.UUID(self.payload)),
      'created_at': self.created_at
    }, indent=4, sort_keys=True)

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
  # print(inspect(ID))
  print(payload(ID))

if __name__ == '__main__':
  main()
