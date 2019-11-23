#!/usr/bin/env python3

from functools import reduce

BASE_62 = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'

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

SKUID = '0ujzPyRiIAffKhBux4PvQdDqMHY'
RAW = '066A029C73FC1AA3B2446246D6E89FCD909E8FE8'

BITS_PER_BYTE   =  8
BYTES_PAYLOAD   = 16
BYTES_SKUID     = 20
BYTES_TIMESTAMP =  4

MAX_SKUID_ENCODED_LENGTH = 27
MAX_SKUID_DECODED_LENGTH = len(str(2**(BITS_PER_BYTE*BYTES_SKUID))) + 1

def format_skuid(id):
  return '0'*(MAX_SKUID_ENCODED_LENGTH - len(id)) + id


def decode(id):
  formated_id = format_skuid(id)

  def decimal(item):
    digit, exp = item
    return (62**exp)*TABLE_DECODE[digit]
  
  return sum(map(decimal, zip(reversed(id), range(62))))

def main():
  print(hex(decode(SKUID)))
  print(hex(int(RAW, base=16)))
  print(MAX_SKUID_DECODED_LENGTH)
  assert hex(decode(SKUID)) == hex(int(RAW, base=16))


if __name__ == '__main__':
  main()
