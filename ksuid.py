#!/usr/bin/env python3

from collections import namedtuple
from datetime import datetime
from string import hexdigits
from typing import NamedTuple

import json
import string
import uuid

BASE52 = string.ascii_letters
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

# COMO GARANTIR QUE OS IDs sao praticamente unicos
# https://towardsdatascience.com/are-uuids-really-unique-57eb80fc2a87

# https://en.wikipedia.org/wiki/Base58

# https://firebase.googleblog.com/2015/02/the-2120-ways-to-ensure-unique_68.html
# https://gist.github.com/mikelehen/3596a30bd69384624c11
# A push ID contains 120 bits of information.
#   The first 48 bits are a timestamp
#    The timestamp is followed by 72 bits of randomness

# https://en.wikipedia.org/wiki/Base64
#     ler sobre padding

# how-do-i-generate-a-unique-id-using-uuid-which-starts-with-an-alphabet
# https://stackoverflow.com/questions/19578833/

scheme = {
  'base58': {
    'bitcoin': '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz',
    'tinyurl': '123456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ'
  },
  'base62': {
    'segmetio': '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
  },
  'base64': {
    'firebase' : '-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz',
    'firestore': '',
    'unix'     : 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
  }
}

scheme2 = {
  'base58': {
    'alphabets': {
      'bitcoin': '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz',
      'tinyurl': '123456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ'
    },
    'encode': {},
    'decode': {},
  },
  'base62': {
    'alphabets': {
      'firebase': '',
      'segmetio': '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
    },
    'encode': {},
    'decode': {},
  },
  'base64': {
    'alphabets': {},
    'encode': {},
    'decode': {},
  }
}

KSUID_EPOCH_ISO8601 = '2014-05-13T16:53:20.000Z'
KSUID_EPOCH_TIMESTAMP = 14e8
KSUID_PAYLOAD = 0x00000000ffffffffffffffffffffffffffffffff

# https://en.wikipedia.org/wiki/Base58
#    exclude O,0, l, +, / to avoid human error
# https://stackoverflow.com/questions/695438/safe-characters-for-friendly-urls
# https://www.ietf.org/rfc/rfc3986.txt

# ASCII sorted
BASE_58_BITCOIN = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

# NOT ASCII sorted
BASE_58_SHORT_URL = '123456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ'

ascii_unreserved = ''.join([
  '+',
  '-',
  string.digits,
  '=',
  string.ascii_uppercase,
  '_',
  string.ascii_lowercase,
  '~'
])


# https://en.wikipedia.org/wiki/Base64
#  '=' padding is used to force 64-bits encoding matching
ascii_base64 = ''.join([
  string.digits,
  string.ascii_uppercase,
  string.ascii_lowercase,
  '+', # posso substituir por URL friendly
  '/', # PRECISO substituir por URL friendly
])

ID = '0ujzPyRiIAffKhBux4PvQdDqMHY'
RAW = 0x066A029C73FC1AA3B2446246D6E89FCD909E8FE8

BITS_PER_BYTE   =  8     #   1-byte  or   8-bits
BYTES_PAYLOAD   = 16     #  16-bytes or 128-bits
BYTES_KSUID     = 20     #  20-bytes or 160-bits
BYTES_TIMESTAMP =  4     #   4-bytes or  32-bits

KSUID_MIN = 0x0
KSUID_MAX = 2**160 - 1
MAX_KSUID_ENCODED = 'aWgEPTl1tmebfsQzFP4bxwgy80V'

MAX_KSUID_ENCODED_LENGTH = len(MAX_KSUID_ENCODED)

# Returns a new ObjectId value. The 12-byte ObjectId value consists of:
#  a 4-byte timestamp (exact same timestamp size)
#  a 5-byte random value (ksuid fits here)
#  a 3-byte counter, starting with a random value.

# chocking https://injuryfacts.nsc.org/all-injuries/preventable-death-overview/odds-of-dying/
# 7 billion at the same time creating 30-MOLs at the millisecond
#   5 milisecond abelha, beija-flor
# 400 milisecond abelha

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
  @property
  def id(self):
    return "asdf"
  payload    : int = 0
  timestamp  : int = 0

  def __str__(self):
    return json.dumps({
      '_id': self.id,
      'timestamp': self._isotime(self.timestamp),
      'payload': str(uuid.UUID(self.payload)),
    }, sort_keys=True)

  @staticmethod
  def _isotime(timestamp):
    moment = datetime.fromtimestamp(timestamp)
    return '%sZ' % moment.isoformat(timespec='milliseconds')

def inspect(id):
  if (type(id) == str) and set(hexdigits).issuperset(id):
    return inspect(int(id, base=16))

  if (type(id) == str) and set(BASE_62).issuperset(id):
    return inspect(decode(id))

  if (type(id) == int) and (KSUID_MIN <= id <= KSUID_MAX):
    return KSUID(payload(id), timestamp(id))

  msg = 'expected id of type int or str, not %s' % type(id).__name__
  raise TypeError(msg)

def main():
  print(inspect('0oqjvob6nFFOVLKFnJj8Ec6kVnx'))
  print(timestamp('0oqjvob6nFFOVLKFnJj8Ec6kVnx'))
  print(format(timestamp(ID), 'x'))
  

if __name__ == '__main__':
  main()
