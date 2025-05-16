#TRUSTED 93d74b4d80a583d41e06743f0a9d63c07e4165cb1abc61970e11ff760338ef30527afb218c478c8af7d11629b8e8dbade3a6803af81db9e355c265a760784891099a93aeed8fc37651d4b919944891dfcbc2435603548e0a48ae64fd31409d27647b816438eebe69015e4d1e37fdf363d3f0f20ddfee00734873ad91440edd70926792453e3d530fa459617cf3041e67a02a9ef2927208e0b6ef1acb24a995e39064f02061475d7b54f78f7d5eb27213ab4cd0ede06c4c6972252596af9ef97b180725e4210d1857cf6a5554d83921f093d61b1a3ca608c62f48678c16c496653245b4e21873287296210b6587bfdca9d61382732bf4129b886960f8594edbbadb5a33c45897fcf5c36642bc5f534144a1371401a4e1b7dda2b67fc90560e00852a27bc48612f0a1de12263cb61f112492ad4e37bcea14b03ef05090b3f85346945cfc84c34296df3d5c2042b7bd4daa631fac8cda20975ad6ea9122b6eb44fbc1d5e06ea1e336bce5093157990b7562a8daf9afa201cedc45aa8cadb88b8261771d2d2d3e7c028ed1742c6aa3d8b073052ff69ddf356b4c2c647187f82816bad1fab60ef267c0ba67301f600c83cd5674e05df1d6ed38acb02f41647030e67a4144a556b8e735e4bb3386acbf35203126e3e52df69a964748a6730150f72988a76eae66fce379628c857ddd4f5da8991132172357e4791f32b4bfaa906c70e8
#TRUST-RSA-SHA256 89694832a96555afc01c717d79ce4e05137f350cbf7ed22c5451b904ce76fb4b6d380f380e3ec35f92b34f13fe7583580c3049f655dc48b5c47b487130f3915d8085ba10775083e6fe172bc6621ec2d8a90eec07d3f50f2cbb321742d4e60b951304cda9660426c697ab5dcd0dd6770523f537382f3a3d6437a46d0132a860caf3033693753c35ab8be3d34377988f740aacde1b3355281d91b62804fed0e748d934934f1cdc14b393626f1fac86eee8a369c1ae9031cc2325aac590d8b043ac81350c1875117f8b6a152665b26ddbf97ee5d53ce7a43c134c23448b01718207e850ee34c0df8285a5c7a4b9766e6afc727d31e5d061e16936320addaf9834c065704760e5ec9415fb62fc0147815cc8c609c8644c64e488056c6d18fb15216f29b7c7f37f507a8bdbdff352c15b3e5a31f9dc77a47e59b037016be97563b31e32ac05e28cc08565797c826cf3dca0aa51dc5091815514d9f1304a4d7ecc497f5d198622348d9f17c04ead5014ed6377f2fc3f4ab5bafc2e365ecdc46b3631ad26478a4dea3ad7d21b1773d5b5037a4aa8348ffa4b90ffd0c703fbb7981d681fcea7d773ea5aa981edab829787b82ea8598dd7866ac445326274cc8369e7ba244c601f8b4c55c68cb458cc8ce6cca7e40c7bfa59fc2b241cdec8a9c77bee3a686c08fce1e8a9cf1488fd12d9637715b035bf9d21973bd58bbf5c3779cab45025

###
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
# charset_func.inc
# Revision: 1.11
###

include("compat_shared.inc");
include("byte_func.inc");

global_var EBCDIC_CHAR_CODE_SET_ID_819 = raw_string(      # default on most systems using EBCDIC.
  0000, 0001, 0002, 0003, 0234, 0011, 0206, 0177, 0227, 0215, 0216, 0013, 0014, 0015, 0016, 0017,
  0020, 0021, 0022, 0023, 0235, 0205, 0010, 0207, 0030, 0031, 0222, 0217, 0034, 0035, 0036, 0037,
  0200, 0201, 0202, 0203, 0204, 0012, 0027, 0033, 0210, 0211, 0212, 0213, 0214, 0005, 0006, 0007,
  0220, 0221, 0026, 0223, 0224, 0225, 0226, 0004, 0230, 0231, 0232, 0233, 0024, 0025, 0236, 0032,
  0040, 0240, 0342, 0344, 0340, 0341, 0343, 0345, 0347, 0361, 0242, 0056, 0074, 0050, 0053, 0174,
  0046, 0351, 0352, 0353, 0350, 0355, 0356, 0357, 0354, 0337, 0041, 0044, 0052, 0051, 0073, 0254,
  0055, 0057, 0302, 0304, 0300, 0301, 0303, 0305, 0307, 0321, 0246, 0054, 0045, 0137, 0076, 0077,
  0370, 0311, 0312, 0313, 0310, 0315, 0316, 0317, 0314, 0140, 0072, 0043, 0100, 0047, 0075, 0042,
  0330, 0141, 0142, 0143, 0144, 0145, 0146, 0147, 0150, 0151, 0253, 0273, 0360, 0375, 0376, 0261,
  0260, 0152, 0153, 0154, 0155, 0156, 0157, 0160, 0161, 0162, 0252, 0272, 0346, 0270, 0306, 0244,
  0265, 0176, 0163, 0164, 0165, 0166, 0167, 0170, 0171, 0172, 0241, 0277, 0320, 0335, 0336, 0256,
  0136, 0243, 0245, 0267, 0251, 0247, 0266, 0274, 0275, 0276, 0133, 0135, 0257, 0250, 0264, 0327,
  0173, 0101, 0102, 0103, 0104, 0105, 0106, 0107, 0110, 0111, 0255, 0364, 0366, 0362, 0363, 0365,
  0175, 0112, 0113, 0114, 0115, 0116, 0117, 0120, 0121, 0122, 0271, 0373, 0374, 0371, 0372, 0377,
  0134, 0367, 0123, 0124, 0125, 0126, 0127, 0130, 0131, 0132, 0262, 0324, 0326, 0322, 0323, 0325,
  0060, 0061, 0062, 0063, 0064, 0065, 0066, 0067, 0070, 0071, 0263, 0333, 0334, 0331, 0332, 0237
);

global_var EBCDIC_CHAR_CODE_SET_ID_1047 = raw_string(     # default on OS390 systems.
  0000, 0001, 0002, 0003, 0234, 0011, 0206, 0177, 0227, 0215, 0216, 0013, 0014, 0015, 0016, 0017,
  0020, 0021, 0022, 0023, 0235, 0012, 0010, 0207, 0030, 0031, 0222, 0217, 0034, 0035, 0036, 0037,
  0200, 0201, 0202, 0203, 0204, 0205, 0027, 0033, 0210, 0211, 0212, 0213, 0214, 0005, 0006, 0007,
  0220, 0221, 0026, 0223, 0224, 0225, 0226, 0004, 0230, 0231, 0232, 0233, 0024, 0025, 0236, 0032,
  0040, 0240, 0342, 0344, 0340, 0341, 0343, 0345, 0347, 0361, 0242, 0056, 0074, 0050, 0053, 0174,
  0046, 0351, 0352, 0353, 0350, 0355, 0356, 0357, 0354, 0337, 0041, 0044, 0052, 0051, 0073, 0136,
  0055, 0057, 0302, 0304, 0300, 0301, 0303, 0305, 0307, 0321, 0246, 0054, 0045, 0137, 0076, 0077,
  0370, 0311, 0312, 0313, 0310, 0315, 0316, 0317, 0314, 0140, 0072, 0043, 0100, 0047, 0075, 0042,
  0330, 0141, 0142, 0143, 0144, 0145, 0146, 0147, 0150, 0151, 0253, 0273, 0360, 0375, 0376, 0261,
  0260, 0152, 0153, 0154, 0155, 0156, 0157, 0160, 0161, 0162, 0252, 0272, 0346, 0270, 0306, 0244,
  0265, 0176, 0163, 0164, 0165, 0166, 0167, 0170, 0171, 0172, 0241, 0277, 0320, 0133, 0336, 0256,
  0254, 0243, 0245, 0267, 0251, 0247, 0266, 0274, 0275, 0276, 0335, 0250, 0257, 0135, 0264, 0327,
  0173, 0101, 0102, 0103, 0104, 0105, 0106, 0107, 0110, 0111, 0255, 0364, 0366, 0362, 0363, 0365,
  0175, 0112, 0113, 0114, 0115, 0116, 0117, 0120, 0121, 0122, 0271, 0373, 0374, 0371, 0372, 0377,
  0134, 0367, 0123, 0124, 0125, 0126, 0127, 0130, 0131, 0132, 0262, 0324, 0326, 0322, 0323, 0325,
  0060, 0061, 0062, 0063, 0064, 0065, 0066, 0067, 0070, 0071, 0263, 0333, 0334, 0331, 0332, 0237
);


##
# Converts an ASCII string to EBCDIC
#
# @param str ASCII string to convert
# @param ccsid CCSID (EBCDIC character set) to convert to
#
# @return EBCDIC representation of 'str'
##
function ascii2ebcdic(str, ccsid)
{
  if (isnull(str)) return NULL;

  local_var c, i, l, res, table;
  l = strlen(str);

  if (ccsid == 1047) table = EBCDIC_CHAR_CODE_SET_ID_1047;
  else table = EBCDIC_CHAR_CODE_SET_ID_819;

  res = "";
  for (i=0; i<l; i++)
  {
    c = str[i];
    res += raw_string(stridx(table, c));
  }
  return res;
}

##
# Converts an EBCDIC string to ASCII
#
# @param str EBCDIC string to convert
# @param ccsid CCSID (character set) of 'str'
#
# @return ASCII representation of 'str'
##
function ebcdic2ascii(str, ccsid)
{
  if (isnull(str)) return NULL;

  local_var c, i, l, res, table;
  l = strlen(str);

  if (ccsid == 1047) table = EBCDIC_CHAR_CODE_SET_ID_1047;
  else table = EBCDIC_CHAR_CODE_SET_ID_819;

  res = "";
  for (i=0; i<l; i++)
  {
    c = ord(str[i]);
    res += table[c];
  }
  return res;
}


##
# Bool check if an item is within printable
# ascii range
#
# @param [char:char] the character to check
#
# return bool True if printable
##
function is_ascii_printable(char)
{
  local_var c;

  # Accept argument anonymously.
  if (isnull(char)) char = _FCT_ANON_ARGS[0];
  if (isnull(char))
  {
    err_print("is_ascii_printable(): missing required arg 'char'");
    return FALSE;
  }

  if (strlen(char) != 1) return FALSE;

  # 9=TAB, 10=LineFeed, 13=CarriageReturn
  # 32-126(0x20-0x7E) is the ascii printable range
  if (((ord(char) > 31) && (ord(char) < 127)) ||
       (ord(char) == 9) || (ord(char) == 10) ||
       (ord(char) == 13) )
  {
    return TRUE;
  }

  return FALSE;
}

##
# remove all non-printable chars from a string
#
# @param [string:string] string to parse
# @param [addspace:bool] if TRUE, the string will
#         contain a space for every set of one or more
#         non-printable characters
#
# @return string the ascii printable clean string
#
# @remark Because the string is passed by value
#    and not ref, nullbytes will cut the string
#    down. This function should not be used to
#    strip out null bytes. Use the example here.
#    example: if (var[i] == raw_string(0))
##
function get_ascii_printable(string, addspace)
{
  local_var asciiString, stringLen, i, whitespace=0;
  if (empty_or_null(addspace))
    addspace = FALSE;

  stringLen = strlen(string);
  asciiString = "";
  for (i=0;i<stringLen;i++)
  {
    # 9=TAB, 10=LineFeed, 13=CarriageReturn
    # 32-126(0x20-0x7E) is the ascii printable range
    if (((ord(string[i]) > 31) && (ord(string[i]) < 127)) ||
         (ord(string[i]) == 9) || (ord(string[i]) == 10) ||
         (ord(string[i]) == 13) )
    {
      asciiString += string[i];
      whitespace = 0;
    }
    else if (whitespace == 0 && addspace)
    {
      asciiString += ' ';
      whitespace++;
    }
  }

  return asciiString;
}

##
#
##
function hex2str(badchars)
{
  local_var xlat,hs,s,i,j, hx;

  hs=_FCT_ANON_ARGS[0];
  s="";

  for (i=0; i<256; ++i) xlat[substr(hex(i),2)]=raw_string(i);

  for (j=0; j<strlen(hs)/2; ++j)
  {
    hx = substr(hs,2*j,2*j+1);
    if (!isnull(badchars[hx]))
    {
      s += badchars[hx];
      continue;
    }

    s += xlat[hx];
  }

  return s;
}

##
# Take a value and return an array of 
# values as shown
# raw - What was sent in
# hex - the value input converted to hex
# ascii - filter out only ascii printable items
#
# @param [val:raw] value to get converted
# 
# @return array of values raw,hex,ascii
##
function get_raw_ascii_hex_values(val)
{
  local_var ret, hexval, asciival;

  ret = make_array();
  hexval = hexstr(val);
  asciival = get_ascii_printable(string:val);
  ret['raw'] = val;
  ret['hex'] = hexval;
  ret['ascii'] = asciival;

  return ret;
}

##
# ROT13
##
function rot13(val)
{
  local_var i, j, ret, c, alpha, letter;

  alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

  for (i = 0; i < strlen(val); i++)
  {
    c = val[i];
    for (j = 0; j<strlen(alpha); j++)
    {
      if (c == alpha[j])
      {
        if (j >= 0 && j <= 12) c = alpha[j+13];
        else if (j >= 13 && j <= 25) c = alpha[j-13];
        else if (j >= 26 && j <= 38) c = alpha[j+13];
        else if (j >= 39 && j <= 52) c = alpha[j-13];

        break;
      }
    }

    ret += c;
  }

  return ret;
}

##
# Converts utf-16 encoded bytes to ascii.
#
# @param [s:string] The utf-16 bytes to convert.
# @param [pos:int]  Position within the string to start the conversion.
#
# @return Returns an ascii string representation of the input string.
# @remark This function does not do language or character conversion, it just
#         returns the non-null characters from the input string that are past
#         the utf-16 BOM, if it is present.
# @remark BOM reference: https://www.w3.org/TR/html4/charset.html#h-5.2.1.1
##
function utf16_to_ascii(s, pos)
{
  var c1, c2;
  var str = "";

  if(isnull(pos) || typeof(pos) != "int")
    pos = 0;

  if(isnull(s))
    return NULL;

  var length = strlen(s);

  if(pos >= length)
    return str;

  for(var i = pos; i < length; i += 2)
  {
    c1 = getbyte(blob:s, pos:i);
    if(i + 1 < length)
      c2 = getbyte(blob:s, pos:i + 1);
    else
      c2 = 0x00;

    # Break on null, handle BOM
    if(c2 == 0x00 && c1 == 0x00) break;
    if(i == pos && c2 == 0xFF && c1 == 0xFE) continue;
    if(i == pos && c2 == 0xFE && c1 == 0xFF) continue;

    # Strip internal NULLs There is no way to convert non-latin UTF-16 to ASCII
    if(c1 != 0x00)
      str += raw_string(c1);

    if(c2 != 0x00)
      str += raw_string(c2);
  }

  return str;
}

