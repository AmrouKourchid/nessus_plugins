#TRUSTED 3864431eb338fc4f4201d34ace979a44c86b7e08134dc882e2bc1fec21a93c7c2282a27add690f6928bee62f72f6ec7dd124c7a5055032ae346ffe7735b4b5579d33fbd2d64465df88a58a76972f5332f9e9b3052b3132541ad5f7f64dfdd6741ab18692dfd2b60f5d134acde5484644d6accbc4b72e24ef27fdb51baa17c8b517b563743f196b8b26961f060795055c1254061cbb0825c3436d16664a9996d1deb7f7a1b37d58142d9ac7b0ae8fbaa9017ec37afb58097aa08f0131be6ead55511f9a340de7219054632081b3979e901efea024879554fe83c1a78d1c29b3672926edd0148a14ea6bb363cab4dd7b4eb964bf65d2c8a4ff19364fb0357e165a088acc10e95df8422493788c8098b8ba5b4dd3b1b0093f3c4830a027d4bd49aadc3cfc26f4b0a09c0e6ec48c21f76075b67e0df8aea6d5f1c7f7ef5ce3aa0c95108656b0fc87631e0675ed1de6cda8c4d6378d489f3de0797227140621d2566b144c36e6699986b61613a937e7585b39fac55affe4d5259ea267561cd9576e696a15f49c157f5b4bc18109773a22935372ba84fdf7dfe05d4dda9d00095d9ca23b5051d88541cc46019ae4e8fb1e4e88a210dcf528f794fdd2d6b822f8243faa81ec35226566363248a9d152f67a3d7cd5398f64026bd4455575e296bd24c109141a43e9f87634cf1949ad38885ced73f08f7cbaa92385c13af228ad9f6bf214
# -*- Fundamental -*-
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# stream_func.inc
#
# Revision: 1.3

include ("byte_func.inc");

global_var __stream, __stream_pos;

__stream = NULL;
__stream_pos = 0;


#---------------------------------------------------------#
# Function    : stream_init                               #
# Description : Initializes a new stream                  #
# Return      : stream handle                             #
#---------------------------------------------------------#

function stream_init()
{
 local_var data, stream, s;
 data = _FCT_ANON_ARGS[0];

 s = __stream_pos++;

 stream[0] = data;           # data
 stream[1] = 0;              # pos
 stream[2] = strlen(data);   # len
 stream[3] = 0;              # error

 __stream[s] = stream;
 return s;
}


#---------------------------------------------------------#
# Function    : stream_end                                #
# Description : Frees stream memory                       #
# Return      : No return value                           #
#---------------------------------------------------------#

function stream_end()
{
 local_var s;
 s = _FCT_ANON_ARGS[0];

 __stream[s] = NULL;
}


function stream_is_end()
{
 local_var s;
 s = _FCT_ANON_ARGS[0];

 return (__stream[s][1] >= __stream[s][2]);
}


function stream_get_data()
{
 local_var s, n, tmp;
 s = _FCT_ANON_ARGS[0];
 n = _FCT_ANON_ARGS[1];

 if (n == 0 || !__stream[s] || __stream[s][1] + n > __stream[s][2])
   return NULL;

 tmp = substr(__stream[s][0], __stream[s][1], __stream[s][1]+n-1);
 __stream[s][1] = __stream[s][1] + n;

 return tmp;
}

function stream_get_pos()
{
 local_var s;
 s = _FCT_ANON_ARGS[0];

 return __stream[s][1];
}

function stream_get_length()
{
 local_var s;
 s = _FCT_ANON_ARGS[0];

 return __stream[s][2];
}

function stream_get_dword()
{
 local_var s, buf;
 s = _FCT_ANON_ARGS[0];

 buf = stream_get_data(s, 4);
 return getdword(blob:buf, pos:0);
}

function stream_get_word()
{
 local_var s, buf;
 s = _FCT_ANON_ARGS[0];

 buf = stream_get_data(s, 2);
 return getword(blob:buf, pos:0);
}

function stream_get_byte()
{
 local_var s, b;
 s = _FCT_ANON_ARGS[0];

 b = stream_get_data(s, 1);
 return ord(b);
}

function stream_get_long()
{
 local_var s;
 s = _FCT_ANON_ARGS[0];

 return stream_get_dword(s);
}

function stream_get_ulong()
{
 local_var s;
 s = _FCT_ANON_ARGS[0];

 return stream_get_dword(s);
}

function stream_get_ushort()
{
 local_var s;
 s = _FCT_ANON_ARGS[0];

 return stream_get_word(s);
}

function stream_get_short()
{
 local_var s, v;
 s = _FCT_ANON_ARGS[0];

 v = stream_get_word(s);
 if (v >= 0x8000) v = 0xFFFF0000 | v;

 return v;
}

function unicode_to_ascii()
{
 local_var s, len, i, tmp;
 s = _FCT_ANON_ARGS[0];

 tmp = NULL;

 len = strlen(s);
 for (i=0; i<len; i=i+2)
 {
  tmp += s[i];
 }

 return tmp;
}

function stream_get_b_varchar()
{
 local_var len;
 local_var s;
 s = _FCT_ANON_ARGS[0];

 len = stream_get_byte(s) * 2;
 if (len == 0) return NULL;

 return unicode_to_ascii(stream_get_data(s, len));
}

function stream_get_b_varbyte()
{
 local_var len;
 local_var s;
 s = _FCT_ANON_ARGS[0];

 len = stream_get_byte(s);
 if (len == 0) return NULL;

 return stream_get_data(s, len);
}

function stream_get_us_varchar()
{
 local_var len;
 local_var s;
 s = _FCT_ANON_ARGS[0];

 len = stream_get_word(s) * 2;
 if (len == 0) return NULL;

 return unicode_to_ascii(stream_get_data(s, len));
}

function stream_get_length_binary()
{
 local_var s, b;
 s = _FCT_ANON_ARGS[0];

 b = stream_get_byte(s);

 return stream_get_data(s, b);
}

function stream_get_length_string()
{
 local_var s, len, tmp, i;
 s = _FCT_ANON_ARGS[0];

 s = stream_get_length_binary(s);
 len = strlen(s);

 tmp = NULL;
 for (i=0; i<len; i++)
 {
  if (s[i] == '\0') break;

  tmp += s[i];
 }

 return tmp;
}

function stream_get_null_string()
{
 local_var s, b, tmp;
 s = _FCT_ANON_ARGS[0];

 tmp = NULL;

 while(1)
 {
  b = stream_get_data(s, 1);
  if (ord(b) == 0) break;

  tmp += b;
 }

 return tmp;
}

function stream_get_remaining_length()
{
  local_var s;
  s = _FCT_ANON_ARGS[0];

  return stream_get_length(s) - stream_get_pos(s);
}
