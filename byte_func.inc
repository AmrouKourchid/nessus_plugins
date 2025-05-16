#TRUSTED 5d1de6eca88a0e5871c5c8c450a5ac3ff19997a7ceb21e54ef3a9c966d5e745351256eb9431be4680430d6318b9e8827f8d6cf48fe57d399206b58c9f406bcd16be54715e12deaad018e8929f230803b25886745399b314d6db62c16b53006ac03963a4b34496dde1810b672316eda6e2a1492527bec79ce3191511c102271b564519afe59174bc28dfebbcc6d99a93bf717c40c06f292228364ed5bdfc06f890fc4794d61f2f68b4f6510e8a97de88b84d18c025749dabf8a774740c9348a8cd42be3e3135183ead1aaa8bccdf9ff9a41bb67a3b3a37962efb75f92f7470c419663661edacf7a576cb7fe8632978ec06c521b1982255099b023146eeaaea10b258e91e8a92cfb2e888b02b2882abf44866e5ac00d96b34b3b776afbb7e02ac49248a0ac412d8ffc0160aec1c836ec062490429c7a4a89a78ac1b441c630c2d9101cd58b842a5052e8761376c964cc6b9f356b06b5588df2dfb7dc4dd0a8a05b00fb6b83adcb656c1cf794f13957a0fd7d96a6eedd4994f4482cae581d4f510e1509d6bc5ded450e18e2dadb38ebd363593d1501d7986d5f37eb3189cb666420ecf6f5490a640598ce9e1c7e9a412bb8781c6eec1b90a4a13eb96b6204f2d956e380d82322b6a5dbeafbde6ad54759f17e69a83bbbe3e051e3dc37a3dc39ddbd1a69ead811d536de16eb8a6808bb34f5eecc88b8606e0b4ac63b4daea020cf20
###
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security Inc.
#
# @NOGPL@
#
# byte_func.inc
#
# Revision: 1.13
##

include("compat_shared.inc");
include("charset_func.inc");

######################################################################
# Byte Order Functions
######################################################################

global_var BYTE_ORDER_BIG_ENDIAN, BYTE_ORDER_LITTLE_ENDIAN;
BYTE_ORDER_BIG_ENDIAN = 1;
BYTE_ORDER_LITTLE_ENDIAN = 2;

global_var __byte_order_index, __byte_order_stack;
__byte_order_index = 0;
__byte_order_stack = make_list(BYTE_ORDER_BIG_ENDIAN);

function get_byte_order()
{
  return __byte_order_stack[__byte_order_index];
}

function pop_byte_order()
{
  # Never pop our default byte order.
  if (__byte_order_index == 0)
    return;

  __byte_order_stack[__byte_order_index--] = NULL;
}

function push_byte_order()
{
  __byte_order_stack[++__byte_order_index] = _FCT_ANON_ARGS[0];
}

function set_byte_order()
{
  # Overwrite all byte order settings.
  __byte_order_index = 0;
  __byte_order_stack = make_list(_FCT_ANON_ARGS[0]);
}

#-----------------------------------------------------------------#
# Convert network long (buffer) to long                           #
#-----------------------------------------------------------------#
function ntol(buffer,begin)
{
 local_var len;

 if (isnull(buffer))
   return 0;

 len = 16777216*ord(buffer[begin]) +
       ord(buffer[begin+1])*65536 +
       ord(buffer[begin+2])*256 +
       ord(buffer[begin+3]);

 return len;
}

##
# Convert integer to 32-bit network representation.
#
# @param i Integer to convert.
#
# @remark The i parameter may also be given anonymously.
#
# @return String representing 32-bit integer.
##
function raw_int32(i)
{
  if (isnull(i))
    i = _FCT_ANON_ARGS[0];

  return raw_string(
    (i >> 24) & 255,
    (i >> 16) & 255,
    (i >>  8) & 255,
    (i      ) & 255
  );
}

##
# Convert integer to 8-bit network representation.
#
# @param i Integer to convert.
#
# @remark The i parameter may also be given anonymously.
#
# @return String representing 8-bit integer.
##
function raw_int8(i)
{
  if (isnull(i))
    i = _FCT_ANON_ARGS[0];

  return raw_string(i & 255);
}

######################################################################
# Byte Emission Functions
######################################################################

function mkpad()
{
  local_var l;

  l = _FCT_ANON_ARGS[0];
  if (isnull(l))
    l = 0;

  return crap(data:'\0', length:l);
}

function mkbyte()
{
  return raw_string(0xFF & _FCT_ANON_ARGS[0]);
}

function mkword(order)
{
  local_var l;

  l = _FCT_ANON_ARGS[0];


  if (isnull(order))
    order = get_byte_order();

  if (order == BYTE_ORDER_BIG_ENDIAN)
    return raw_string((l >> 8) & 0xFF, l & 0xFF);
  else
    return raw_string(l & 0xFF, (l >> 8) & 0xFF);
}

function mkdword(order)
{
  local_var l;

  if (isnull(order))
    order = get_byte_order();

  l = _FCT_ANON_ARGS[0];

  if (order == BYTE_ORDER_BIG_ENDIAN)
    return raw_string(
      (l >> 24) & 0xFF,
      (l >> 16) & 0xFF,
      (l >>  8) & 0xFF,
      l & 0xFF
    );
  else
    return raw_string(
      l & 0xFF,
      (l >>  8) & 0xFF,
      (l >> 16) & 0xFF,
      (l >> 24) & 0xFF
    );
}

######################################################################
# Byte Parsing Functions
######################################################################

function getbyte(blob, pos)
{
  if (isnull(blob))
    blob = _FCT_ANON_ARGS[0];

  if (isnull(pos))
    pos = 0;

  if (pos < 0)
    return NULL;

  if (pos + 1 > strlen(blob))
    return NULL;

  return ord(blob[pos]);
}

function getword(blob, order, pos)
{
  local_var s;

  if (isnull(blob))
    blob = _FCT_ANON_ARGS[0];

  if (isnull(order))
    order = get_byte_order();

  if (isnull(pos))
    pos = 0;

  if (pos < 0)
    return NULL;

  if (pos + 2 > strlen(blob))
    return NULL;

  s = substr(blob, pos, pos + 1);

  if (order == BYTE_ORDER_BIG_ENDIAN)
    return ord(s[0]) << 8 | ord(s[1]);
  else
    return ord(s[0]) | ord(s[1]) << 8;
}

function getdword(blob, order, pos)
{
  local_var l, s;

  if (isnull(blob))
    blob = _FCT_ANON_ARGS[0];

  if (isnull(order))
    order = get_byte_order();

  if (isnull(pos))
    pos = 0;

  if (pos < 0)
    return NULL;

  if (pos + 4 > strlen(blob))
    return NULL;

  s = substr(blob, pos, pos + 3);

  if (order == BYTE_ORDER_BIG_ENDIAN)
    return
      ord(s[0]) << 24 |
      ord(s[1]) << 16 |
      ord(s[2]) <<  8 |
      ord(s[3]);
  else
    return
      ord(s[0]) |
      ord(s[1]) <<  8 |
      ord(s[2]) << 16 |
      ord(s[3]) << 24;
}

function getqword_shift(blob, order, pos, shift)
{
  local_var end, i, shift1, shift8, start, xx, yy;

  if (isnull(blob))
    blob = _FCT_ANON_ARGS[0];

  if (isnull(order))
    order = get_byte_order();

  if (isnull(pos))
    pos = 0;

  if (isnull(shift))
    shift = 0;

  if (pos < 0)
    return NULL;

  if (pos + 8 > strlen(blob))
    return NULL;

  if (shift < 0)
    return NULL;

  if (shift >= 64)
    return NULL;

  shift8 = shift / 8;
  shift1 = shift - 8 * shift8;

  yy = 0;
  xx = 0;

  if (order == BYTE_ORDER_BIG_ENDIAN)
  {
    start = 4 - shift8;
    if (start < 0)
      start = 0;

    for (i = start; i <= 7 - shift8; i++)
      xx = (xx << 8) | ord(blob[pos + i]);

    if (shift < 32)
      yy = ord(blob[pos + 3 - shift8]);
  }
  else
  {
    end = shift8 + 3;
    if (end > 7)
      end = 7;

    for (i = end; i >= shift8; i--)
      xx = (xx << 8) | ord(blob[pos + i]);

    if (shift < 32)
      yy = ord(blob[pos + shift8 + 4]);
  }

  if (shift1 > 0)
    yy <<= (8 - shift1) + 24;
  else
    yy = 0;

  xx >>>= shift1;

  return (xx | yy);
}

##
# Extracts printable strings from a buffer.
#
# @param  data   buf        Buffer of data to extract strings from.
# @param  int    len        OPTIONAL Length of buffer to search,
#                           defaults to 1024.
# @param  int    min_len    OPTIONAL Minimum length of printable chars
#                           to be considered a string, defaults to 4.
# @param  bool   null_term  OPTIONAL whether or not a string must be
#                           NULL terminated to be considered a string,
#                           defaults to FALSE.
#
# @return list  of strings
##
function get_strings(buf, len, min_len, null_term)
{
  local_var offset, char, string;
  local_var strings;

  strings = make_list();
  string = '';

  if (isnull(buf)) buf = _FCT_ANON_ARGS[0];
  if (isnull(buf))
  {
    err_print("get_strings(): missing required arg 'buf");
    return strings;
  }

  # Set default values.
  if (isnull(len)) len = 1024;
  if (isnull(min_len)) min_len = 4;
  if (isnull(null_term)) null_term = FALSE;

  # Ensure we don't read past the end of the buffer.
  if (len(buf) < len) len = len(buf);

  # Iterate through the buffer up to the max length.
  for (offset = 0; offset < len; offset++)
  {
    # If the current byte is printable add it to the current string.
    # Otherwise if the current byte is the NULL terminator and the
    # string is above the minimum length, add the string to the list
    # of strings.
    char = getbyte(blob:buf, pos:offset);
    if (is_ascii_printable(raw_string(char))) string += raw_string(char);
    else
    {
      if ((!null_term || char == 0) && len(string) >= min_len) strings = make_list(strings, string);
      string = '';
    }
  }

  # Check if we have a valid string at the end of our buffer.
  if (len(string) >= min_len) strings = make_list(strings, string);

  return strings;
}

##
# Get a 24-bit number value.
#
# @param blob Data blob to get the value from.
# @param pos Position with the blob to get the value.
#
# @return A 24-bit integer number.
##
function get_int24(&blob, pos)
{
  local_var v;

  v = getbyte(blob:blob, pos:pos) * 0x10000 +
      getword(blob:blob, pos:pos+1);

  return v;
}

