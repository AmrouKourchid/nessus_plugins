#TRUSTED 8647f98e3f0c78c0fec1bff075a175b63ecc3fb13f0a09c5aea6c88d759d0bd222bcf160aef1230c82ac7ee37e67de1dd49eee7451dc50e491db65b44d8ff057eb4a0046e243fcbbff5fa947ab6bea0b3a77264b977e9686e7e757cdf09c54f1178c2077faadd400c91d44ee35196652011125a63461eab5f125243310a5ac55e6b6e82cfb5caaeede1b21cf884d9faa2f53adf186846343433e457e1a2094b455f88c5b2938e047bbf2f82986fd9ebacd76eeff5d19d97cf0cfa7a08bbc3cb3663ce3cbcceffacc8814cf4c485687015304bd0e519c59afe65b86b0241ca3f5cc0c3b8c34d18bdf0b585de0077f4e9340b93aaa61cf5ccafecfb0c446954067e5516a23a79b18477ab2639bdca7813689e583b6695407ceab994ecbe629de9d1fa234075821448e20a834c89d63e1e3ea6aa73ace8e78417731e8aa0fb0f0f6c3ff66755952d85849482ce95b47dd5bbb037753cc1110026ea64a0d2c5de984687ae8f3c12551f7d50b00903c498c445afc8699455d5d94786b0d87d2379fd065afed0a12b674be48f883aa0211a1f6be2019d47c39416e29a6918e17553a3412f33dc65068106c2fd34c0f3edef34b905c3534d5414ba15d51d72e64e04611c93679684bc36b73c44ccdaf0c8934a1af541d04213d85f2cdc3e602de2b2872c4d5cfb181bc3798c3b8829d03b05fbd7c779c429fa6c7c77f26193ffab3dfda
#TRUST-RSA-SHA256 185f2defe7d71f8aab679e87268c4572e952d701d34e5d7e7d1045a3cffa54ed79e6b079b6d94dd8216005f86c20c0176088c1c0e67fe8757abd69fe0b4731012c56a76c463b8a586edf70aec2f4ae96496de1d2a0a9f1ee65bf34c3e46a4f3433da25c652d30158881f2679d80bdf6c81dea1de502fff5367353f9518e3dde3e69f9006dc9d8d638e35b8d531e025fe59937f13eee9eec5090860307ad4aea1f5e73d8fc63d0815e94bae1162d82642cafef73752150487f482adc9ba1181e16edc419254f5c16f1aaf964fabbc7ccc30bb2c77bb190e9ce65e7584d1e8c6fe7acf3753099d95c1eb03f3a7c35e239c644f935a47ef8ed55d1d38f65100dd473b119e7c49567e084011c400d84a346698fb835f5f4adc7944468321f34e32c6b942d37c0d7abdde8db08b262e30fe58887e74674ae04be10118e775460b373354e1814b0992184a01526e0dc837fd6cfe219326900948534cb566c593c965de3332866a90c107840825659e94dae8684bccbaab955697d0572f207e015cc3a293ad4e9455fef46d854fb78bfcac16424088dfaa8610844ba6f82a3c6017b1dd370a167a06430450d9c209002cc9896b2fe5bf4c50b486d5e5e76f7f4e33138382fe9341c93e45676193ad3b017f944ffd6d898a1d28a26e70287458410bad2a2077f221ee9a0938748e74c51d767d087b0339dba740afeb76b7e69a50ba8770
###
# -*- Fundamental -*-
#
# (C) Tenable Network Security, Inc.
#
#
# An earlier iteration of this file was written by George Dagousset (2002)
#
# This include file is released under the terms of the GPLv2
#
# This include file has functions used to generate a hex dump of data
#
# dump.inc
# Revision: 1.14
###

##
# Generates the hex line number prefix for line "line" of "linenumber".
#
# This function is used by hexdump() to generate the line numbering for its output
#
# For example, the 0th line of 5 will result in "0x00: "
# The 5th line of 500 will result in "0x0040: "
# The amount of padding each offset receives depends on "linenumber" - numbers
# will be padded out (if necessary) so they are the same length as the largest
# possible number.
#
# @param line the number of the current line
# @param linenumber the total number of lines
# @return a line number prefix to be used by hexdump()
##
function line2string (line, linenumber)
{
  var tmp, pos;

  line = line*16;
  tmp = raw_string (
    (line >> 24) & 0xFF,
    (line >> 16) & 0xFF,
    (line >> 8) & 0xFF,
    (line ) & 0xFF
  );

  if (linenumber < 256)
    pos = 3;
  else if (linenumber < 65536)
    pos = 2;
  else if (linenumber < 16777216)
    pos = 1;
  else
    pos = 0;

  return "0x" + toupper(hexstr(substr (tmp, pos, 3))) + ": ";
}


##
# Determines if the given character is ASCII suitable to be displayed in hexdump()
# output (0x20 through 0x7e inclusive).  This excludes control characters such as
# tab and newline.
#
# @param c character to check
# @return TRUE if "c" is between 0x20 and 0x7e inclusive,
#         FALSE otherwise
##
function isprint (c)
{
  if ( (ord(c) >= 0x20) && (ord(c) <= 0x7E) )
    return TRUE;

  return FALSE;
}


##
# does a hex dump of sixteen bytes of data
#
# @param str hex data to dump
# @param line the number of the line being dumped
# @param totallen the total number of lines in the dump
# @return a hex dump of "hex" with a line number prefix
##
function dump_line_and_data(str, linenb, totallen)
{
  var j, len, c, line, data;

  line = line2string (line: linenb, linenumber: totallen);
  len = strlen(str);

  for (j = 0; j < 16; j++)
  {
    if (j < len )
    {
      line = line + " " + toupper(hexstr(str[j]));
      c = str[j];
      if (isprint (c:c))
        data += c;
      else
        data += ".";
    }
    else
    {
      line += "   ";
      data += " ";
    }
  }
  return line + '    ' + data + '\n';
}

##
# does a hex dump of the given data
#
# @param ddata the data to dump
# @return empty string if ddata is NULL or empty, else
#         a hex dump of "ddata"
##
function hexdump (ddata)
{
  var tmp, i, linenumber, len;
  var same_str_cnt, prev_str, prev_adr, str;

  len = strlen(ddata);
  if (len == 0) return '';
  linenumber = len / 16;

  prev_str = NULL; same_str_cnt = 0; prev_adr = 0;

  for (i = 0; i <= linenumber; i++)
  {
    str = substr(ddata, i*16, i*16+15);
    if (! isnull(prev_str))
    {
      if (str == prev_str)
      {
        same_str_cnt ++;
        continue;
      }
      #else if (same_str_cnt == 1)
      #{
      #  tmp += dump_line_and_data(str: prev_str, linenb: i-1, totallen: len);
      #}
      #else if (same_str_cnt > 1)
      else if (same_str_cnt >= 1)
        tmp += '*\n';
    }
    prev_str = str; same_str_cnt = 0;
    tmp += dump_line_and_data(str: str, linenb: i, totallen: len);
  }

  if (same_str_cnt > 0)  # Should not happen!
    tmp += dump_line_and_data(str: prev_str, linenb: i-1, totallen: len);
  return tmp;
}


##
# Displays a hex dump of the given data
#
# @dtitle a string title to give to the hex dump
# @ddata the data to dump
##
function dump( dtitle, ddata )
{
  if( ! isnull( dtitle ) )
    display('---[ ' + dtitle + ' ]---\n' );

  display(hexdump(ddata:ddata));
}

##
# A debug function that recursively prints out a table.
#
# @param table The table to print.
# @param indent [optional] Used internally for recursion.
##
function dump_table(table, indent)
{
  var key;

  if(!indent)
    indent = 0;

  if(typeof(table) == 'array')
  {
    foreach key(keys(table))
    {
      if(typeof(table[key]) == 'array')
      {
        display(crap(data:'\t', length:indent), key, ':\n');
        dump_table(table:table[key], indent:indent+1);
      }
      else
      {
        display(crap(data:'\t', length:indent), key, ': ', table[key], '\n');
      }
    }
  }
  else
  {
    display(crap(data:' ', length:indent), '\n');
  }
}
