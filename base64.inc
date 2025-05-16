#TRUSTED 338d226dc786facc86db017a3d53338f042e464fdd177ad15182f021bab315f7961b7d77efc61fa9bddb90733d9da20d10f6d0cad15961a4fdc3b166c9d4c7a87c11a7401f0d68b078587d15e67750b400defd0909ddd03bf9e730b1f71912f471c1303c5adb32a3589a3a03261e67c45fe37d4f96e3c2b7ed5fce939e2483288df6529deb044fb7872539e6d2d3a71aa1a4071b04c01b63e6cd6ece41b5ad2cb9781dc2691206d01897ba4dba033cdff64bb59c6d3eb0cd3b81a831d3ffb55762f983788ed410ad18c1a22fdb3b35bcb7f2cd9336aaba04fd77805a0452c703703fc78758ed72857ba3365b18bce6629b0f02676f92de2b1c528bf81691f3cf48750ddb8b9205814608784e6ccbc4c4030bee6ff39e3fbfefa50f155f0eea40e70547cdb7b40421b832fef9c9d88a8fbede6d477ec9b09539cba40ef65b7e2a0c1c4a9087b4aeb8cc996a101976d9a25bd6b0ff8e53973fc13e5c244087df320864e6d6c183e96597de423f05f3f1b7c834681a203398f14f1d2c8bf9b3f57b8fcefa9c44658dc45619cae42cfb442ab9790db56a516a99ada0fb3b7ecfad38f28b962bd82e8f886b9db299de56ce8f45a98ae8dde90d2e6de7717169a6806d23ec9591e621c6316edd0487f9f3b13c15756301b7123e754f19a92fd61d4670462e69b78b86ee0ddd6218914f49406d4ab23eb443d92eb5b8c4eafa2b49ce14
#------------------------------------------------------------------------------
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# Revision: 1.0
#

include("byte_func.inc");

# copied from __base64_code of misc_func.inc
global_var __base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

# helper for base64encode(), copied from base64_code() of misc_func.inc
function _base64_code(c)
{
 return(__base64_chars[c]);
}

# helper for base64encode(), copied from pow2() of misc_func.inc
function _pow2(x)
{
 local_var __ret;

 __ret = 1;
 while(x)
  {
  __ret = __ret * 2;
  x = x  - 1;
  }
 return(__ret);
}

##
# Encodes data into a base64 string
#
# @remark copied from base64() of misc_func.inc
# @param str string to encode
# @return base64 encoded version of "str"
##
function base64encode(str)
{
 local_var len, i, ret, char_count, _bits, val, cnt, mul;

 len = strlen(str);
 i = 0;
 ret = "";
 char_count = 0;
 _bits = 0;
 while(i < len)
 {
  _bits = _bits + ord(str[i]);
  char_count = char_count + 1;
  if(char_count == 3)
  {
    val = _bits / 262144;
    ret += string(_base64_code(c:val));
    val = _bits / 4096;
    val = val & 0x3F;
    ret += string(_base64_code(c:val));
    val = _bits / 64;
    val = val & 0x3F;
    ret += string(_base64_code(c:val));
    val = _bits & 0x3F;
    ret += string(_base64_code(c:val));
    char_count = 0;
    _bits = 0;
 }
 else {
       _bits = _bits * 256;
       }
 i = i + 1;
 }

 if(!(char_count == 0))
 {
  cnt = char_count * 8;
  mul = 16;
  mul = mul - cnt;
  mul = _pow2(x:mul);
  _bits = _bits * mul;
  val = _bits / 262144;
  ret += string(_base64_code(c:val));
  val = _bits / 4096;
  val = val & 0x3F;
  ret += string(_base64_code(c:val));
 if(char_count == 1)
 {
  ret = ret + "==";
 }
 else
 {
   val = _bits / 64;
   val = val & 0x3F;
   ret += string(_base64_code(c:val)) + "=";
  }
 }
 return(ret);
}

#-----------------------------------------------------------------#
# Decode base64 string - ported from public domain code           #
#-----------------------------------------------------------------#
function base64decode(str)
{
 local_var len, i, j, k, ret, base64, b64, a,b,c,o;
 len = strlen(str);
 if (len % 4 != 0) return "";

 ret = "";

 base64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

 for (i = 0; i < 256; i++)
   b64[i] = 0;
 for (i = 0; i < strlen(base64); i++)
   b64[ord(base64[i])] = i;

 for(j=0;j<len;j+=4)
 {
   for (i = 0; i < 4; i++)
   {
    c = ord(str[j+i]);
    a[i] = c;
    b[i] = b64[c];
   }

   o[0] = (b[0] << 2) | (b[1] >> 4);
   o[1] = (b[1] << 4) | (b[2] >> 2);
   o[2] = (b[2] << 6) | b[3];
   if (a[2] == ord('='))
     i = 1;
   else if (a[3] == ord('='))
     i = 2;
   else
     i = 3;
   for(k=0;k<i;k++)
      ret += raw_int8(i:o[k]);

   if (i < 3)
     break;
 }

 return ret;
}

