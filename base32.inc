#TRUSTED 89a82b1e49188ad774429c799323739cf42462d26aac94700b7c6abf1b93454429f752c72db888e5a3afa8f4621e145ad78c9a284602d829e2f34849347153f9598286a50d8cf9de33c509d54704747c03c7431ec9be26da5eba4aee37522fd522e7e3042ac1134e40dd5aa24b1bbf45e4f63b83307958688e4866eb556778d857f84ffa7f44c354b79856febb386b47cf61be50fd535456a7cd7f97d70ec7dfe28260a717a36a59d869483e4efd2eb351a1f473dee0a0aba72b0e95e024d62ee10de3e7af919fe0721c37be1d7ddfd381e65aad4c44de104124981f2b4874e28b0a426a980de1913f49e585583c262517e95c90e9f8e5c4116ef13b87b5685c8d5ee7ba6fbc529cd049e5a4846b1c409481ffe2414ad3dd8f5cde9176f533fc710615c43c39d5c3ab6092b70dd3eb17c89a41c6c5bc6fccd96dbb6fd8ef8187ed99894fb0231149fb482b7cc44fcb21173f07c7a0a706068d408e6eb8f644223d7e398989570a81e3eb51599f96109bbbe06585f24f7063ff8fdaaf2bd0b592681b3161dfe66808455e710ea878e58df6b34b36623477c7428609599439623b68c8b2d6224f9a2f2395bb24495696f039513c10862b31893be5c597b40208acf021bd9ed3e0f5cd718b2ce4d4fcb17ca729915fa0138dd1812209d0634c278867d1604cde877560cb9eb49895ee048d82088ace7b2c3581816d7bc683330079
#
# Base32 implementation
#
# Translated from https://github.com/google/google-authenticator-libpam/blob/master/src/base32.c
# Copyright 2010 Google Inc.
# Author: Markus Gutschke
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


function base32_encode(str)
{
  local_var tmp;
  local_var i, n,mod;
  local_var ret;
  local_var pad;
  local_var buffer, next, bitsLeft, count, index;
  local_var Base32Digits;

  Base32Digits = "abcdefghijklmnopqrstuvwxyz234567";
  n = strlen(str);
  pad = NULL;
  count = 0;
  buffer = ord(str[0]);
  next   = 1;
  bitsLeft = 8; 
  while ( bitsLeft > 0 || next < n )
  {
    if ( bitsLeft < 5 )
    {
    if ( next < n )
    {
    buffer <<= 8; 
    buffer = buffer | (ord(str[next++]) & 0xFF);
    bitsLeft += 8;
    }
    else
    {
    pad = 5 - bitsLeft;
    buffer <<= pad;
    bitsLeft += pad;
    }
  }
  index = 0x1F & ( buffer >> (bitsLeft - 5));
  bitsLeft -= 5;
  ret = ret + Base32Digits[index];
  }
  return ret;
}

function base32_decode(str)
{
  local_var buffer, bitsLeft, count;
  local_var i, n, c;
  local_var ret;
  local_var Base32Digits;

  Base32Digits = "abcdefghijklmnopqrstuvwxyz234567";

  str = tolower(str);
  n = strlen(str);
  buffer = 0;
  for (i = 0 ; i < n ; i ++ )
  {
    c = str[i];
    if ( c == ' '  ||  
        c == '\t' || 
        c == '\r' || 
        c == '\n' || 
        c == '-' )  continue;

    buffer <<= 5;

    # Commonly mistyped characters
    if ( c == '0' ) c = 'o';
    else if ( c == '1' ) c = 'l';
    else if ( c == '8' ) c = 'b';

    c = ord(c);

    if ( c >= 0x61 && c <= 0x7a ) # c >= 'a' && c <= 'z' 
      c = (c & 0x1f) - 1;
  else if ( c >= 0x32 && c <= 0x37 ) # c >= '2' && c <= '7' 
      c -= ord('2') - 26;
  else return NULL;

  buffer = buffer | c;
  bitsLeft += 5;
  if ( bitsLeft >= 8 ) 
    {
    ret = ret + raw_string(buffer >> (bitsLeft - 8));
    bitsLeft -= 8; 
    }
  }
  return ret;
}