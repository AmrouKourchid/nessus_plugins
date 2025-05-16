#TRUSTED 17c61c648a70fd574a20daa0e32d1e884e382e9268a83771707e04676fba9983dad1d6f92bbf2fde889dc5c28a0bc32080720d0b98371940435b6f8da09027eda8c6798bc6201ecead886f0f5b5f1bd2f722efd0a9fdafb5b43c1b9269e8f1bf6ee5458dcfa67d29098ba2fb53bc8071822055d0db6ad3127c6e92ba10bfeed8d692f41d38597adbff30de2ad5f9c43deb11b0eed0fb80b14e0fe87416e1667d2f73436f45db231a6437f4b3d6520e9f8dfce777d3dd06b6fe41ec624410d334b1d46bca2cee3381662b588c0b3db6b0e41e8924ca38a020f721de0e52d65ccb20f00a92ab582c37d1a95d768bf8bf8dc359b7176d06f5c335724143074cfbcee4de1d0aa0b5f8e9866f51b5118081349d4a8e7ca2aaca0db38f16786c73b223880addccef1e5b06e0062c6129a23ae78cd5e573f4856d1b119264928062d3c6f1cb3bbf0416028530bfef78c67cf82df9b6a209e90c4d30492c1f15f74d694e109f2259519755590a52e3b40569fe01dbc3b0e59a7851878e51ee0568ca32e8005f5754245ed44dd90fe07d4aa901158b8137c58bf7632fbdcd612d06027465dd30178abfbb3e9d9669d752fd03ac0dcfdfcf86d1eed0b29cfdebc898b2b05fc496aec58329b34fd54dfa3b9218051ed001b6be3680047bb2fd9cb7640cfb60c56129bc6cc56d2ae5e8496cf04645d8a285fe2a00bd5bf2ef15eb3530075e38
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# gunzip.inc
# Revision: 1.4
#

include("byte_func.inc");

function gzip_parse_header()
{
 local_var buf;
 local_var h;
 local_var pos;
 local_var isize;
 
 set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);

 buf = _FCT_ANON_ARGS[0];

 if ( strlen(buf) < 18 ) return NULL;

 h = make_array();
 h["id1"] = substr(buf, 0, 0);
 h["id2"] = substr(buf, 1, 1);
 if ( ord(h["id1"]) != 0x1f || ord(h["id2"]) != 0x8b ) return NULL;
 h["cm"] = substr(buf, 2, 2);
 h["flag"] = substr(buf, 3, 3);
 h["mtime"] = getdword(blob:buf, pos:4);
 h["xfl"]  = substr(buf, 8, 8);
 h["os"] = substr(buf, 9, 9);
 pos = 10;

 if ( ord(h["flag"]) & 4 )
 {
  # Untested
  h["xlen"] = getword(blob:buf, pos:pos); pos += 2;
  pos += h["xlen"];
 }

 if ( ord(h["flag"]) & 8 )
 {
  while ( ord(buf[pos]) != 0 ) pos ++;
  pos ++;
 }

 if ( ord(h["flag"]) & 16 )
 {
  while ( ord(buf[pos]) != 0 ) pos ++;
  pos ++;
 }

 if ( ord(h["flag"]) & 2 )
  pos += 2;

 h["crc32"] = getdword(blob:buf, pos:strlen(buf) - 8);
 h["isize"] = getdword(blob:buf, pos:strlen(buf) - 4);
 h["pos"] = pos;
 return h;
}

global_var _max_gunzip_size;
_max_gunzip_size = 1024 * 1024 * 40;

function set_max_gunzip_size()
{
  local_var size;
  size = int(_FCT_ANON_ARGS[0]);
  if (size <= 0)
    return;

  _max_gunzip_size = size;
}

function get_max_gunzip_size()
{
  return _max_gunzip_size;
}

function gunzip()
{
 local_var header;
 local_var data;

 data = _FCT_ANON_ARGS[0];
 header = gzip_parse_header(data);
 if ( isnull(header) ) return NULL;

 # workaround for VULN-81472
 if (header["isize"] >= get_max_gunzip_size()) return NULL;
 
 return zlib_decompress(data:substr(data, header["pos"], strlen(data) - 8), length:header["isize"]);
}

