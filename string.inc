#TRUSTED 09ca10dc929681a394f19ce70c13ca8bde49db7e82fdf327d53bedabeea5e203ca8e73f248fb8e12ab263dbac8293cb2c17107936c54c651d07f21665fb321220a8762fb0e7cde0d20f22c3a5161ae79ebdaba4c77c8bff2571f8d9f32813652be513d91c7f3b928c330ed71f4b3858a867447a6c151bcc5cbabfb09024351e7188181514aaf41c0c14b3cfc05f86c4dc96e6372271e4ef13b2f1e5b6f2c226ed3a8d37c8f67f16318f6a8cec0c264714a07d6f3fb49fe612fc7c3065c2a77e5abd9d137b714162604e6367ccf640806c2dbd8079d414759f563326fe8506ac455d9e2fee82e56e3d705538e0c7ea59e71e00713b76f5914a149fc834759e032c522b9205036800aeff8c7ef7748caa91f975c63d2e8b4ac46c9672f8c0af929b2052478dc05ead1134154c004749821c47bd338d8098016807febafc06a0dce68612a278482056dde4c1a27562e2ba15f1bd2e2ff19c0bdd5c1cadce6f5cb03304118f67ae8486f292270b458f50820681160c76c1ac7d356b9769a0670534aa32aea604d0f6125cf65d4733b441ed3af2e6bab6e5d6db2a8c551349823a5ef0b2dade3f7aa83769a0c76026ccc031f0577f421b97854dccd64c8ce6bce64f48619e225b8e4186c5d6502727d937f77e6811865df456e77a1a98d46679584fa5b3381554be4d5229fac7d0ed1383aab29432c79c61d99066fc89b8c16308e91
#TRUST-RSA-SHA256 59785e84586a297a8a02bbdb84145dc7ccd59936004bcbd07491b66e07f5e39863de3c7346569e01c46c8e8092d9443b94cadb9575009ce245ed896eed85b1e075866fcc671f63a33492c5040c5efa5fe5490552eff13e629a8c90a342868468f1838da19984bef39984d1773e173b966bf1168ebf8ba530224e1dd6943b97dc529987bf259fc7f300f4380f4a07200de1687a62238606aec30b25e0f9302444845c09bfb57b0efa172da6f5f743fda647822bc8fa5d5c7c45bff0b6668cddbe13faaab2b44b08c3c16845f70acb5972cb5de01d58dd1d18249e419c59809ddf320d8c812fdc197467b7d984469f4ada7c51cfa1b50b5b3daa2e7293d6717d5accff8b7e34a22d991e4d2acea79c1fd2845f0d639facde270e107e321188133d63d635f4e3beb0850699521efd98c23a2b057f3550cd5626f8f2a23c380fbc50a133e14d0e475bb7c395055a5ff0c823a952b334f4ed06f4e7020955cb6e9ded4b50371e47db04deb9c9973798ee24de1781223e32eb1c7045141a5b0a95b72d747e26a1311cb6c1a0d9847f23bdf84e46b0c95e7b6eb9edd1ff42ffcb8ab0d85af020619d23b93768351959715145cd80373c615081be6784ffc12941d4fbca73a33409abd6dee84dd9ec21f611f4fcea4d839476635a9354be1e97f2e26648fd91bc28c3c981d2580b61ed12de663749dab2efb68617d1629309270ed3fb34
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# string.inc
#
# Revision: 1.9
#
include("compat_shared.inc");
include("byte_func.inc");
include("path.inc");
#pragma static(include)
include("string_pack.static");
include("string_printf.static");
#pragma static(include:false)

##
# Check whether an object is a string.
#
# Basically, a wrapper around typeof().
#
# @anonparam obj Object to be examined.
#
# @return TRUE if the object is of type 'data' or 'string'.
##
function is_string()
{
  local_var type;

  type = typeof(_FCT_ANON_ARGS[0]);

  return (type == "data" || type == "string");
}

##
# Return a number of characters from the start of a string.
#
# Basically, a wrapper around substr() that makes life much easier.
#
# @anonparam s The string.
# @anonparam n The number of characters.
#
# @return The first n bytes from string s.
##
function left()
{
  local_var n, s;

  if (max_index(_FCT_ANON_ARGS) != 2)
    return "";

  s = _FCT_ANON_ARGS[0];
  n = _FCT_ANON_ARGS[1];

  if (!is_string(s) || s == "" || n <= 0)
    return "";

  if (n >= strlen(s))
    return s;

  return substr(s, 0, n - 1);
}

##
# Return a number of characters from the end of a string.
#
# @anonparam s The string.
# @anonparam n The number of characters.
#
# @return The last n bytes from string s.
##
function right()
{
  local_var l, n, s;

  if (max_index(_FCT_ANON_ARGS) != 2)
    return "";

  s = _FCT_ANON_ARGS[0];
  n = _FCT_ANON_ARGS[1];

  if (!is_string(s) || s == "" || n <= 0)
    return "";

  l = strlen(s);
  if (n >= l)
    return s;

  return substr(s, l - n, l - 1);
}

##
# Reverse a string.
#
# @anonarg s The string to reverse.
#
# @return The string, reversed.
##
function string_reverse()
{
  local_var i, r, s;

  if (max_index(_FCT_ANON_ARGS) != 1)
    return "";

  s = _FCT_ANON_ARGS[0];
  if (!is_string(s) || s == "")
    return "";

  r = "";
  for (i = strlen(s) - 1; i >= 0; i--)
    r += s[i];

  return r;
}

##
# Convert input -- a string or a number -- to a digit.
#
# @anonparam n Input to convert.
#
# @param base Optional base to use. Default: 16.
# @param ucase If TRUE, return an uppercase digit.
#
# @return A single digit betweeen '0' and 'z', '0' on error.
##
function to_digit(base, ucase)
{
  local_var mask, off, s;

  if (max_index(_FCT_ANON_ARGS) != 1)
    return "0";

  s = _FCT_ANON_ARGS[0];
  if (isnull(s) || s == "")
    return "0";
  s = int(s);

  if (isnull(base))
    base = 16;

  if (base < 2 || base > 36)
    return "0";

  s %= base;

  if (s < 10)
    return string(s);

  if (ucase)
    off = "A";
  else
    off = "a";

  return raw_string(ord(off) + s - 10);
}

##
# Convert a single hexatridecimal / sexatrigesimal digit into decimal.
#
# Typically, the input is '0' - '9' and 'a' - 'f', but values between
# 'g' and 'z' are also accepted (as the values 16 - 35).
#
# @anonparam n The nibble, as a string.
#
# @return An integer betweeen 0 and 35, 0 on error.
##
function from_digit()
{
  local_var n, s;

  if (max_index(_FCT_ANON_ARGS) != 1)
    return 0;

  s = _FCT_ANON_ARGS[0];
  if (!is_string(s) || s == "" || strlen(s) > 1)
    return 0;

  n = ord(tolower(s[0]));

  if (n >= ord("0") && n <= ord("9"))
    return n - ord("0");

  if (n >= ord("a") && n <= ord("z"))
    return n - ord("a") + 10;

  return 0;
}

##
# Convert a string representation of a number of the given base into the
# integer representation. The number can be any size, but NASL only currently
# supports 32-bit integers.
#
# The most common bases are binary (2), octal (8), decimal (10), and
# hexadecimal (16). Any base up to 36 can be used, though, with a - z
# representing 10 - 35.
#
# @remark No handling of overflows is performed.
#
# @remark No handling of digits incompatible with the base is performed.
#
# @anonparam s String to be converted.
#
# @param base Optional base, 10 by default.
#
# @return An unsigned integer representing the value, 0 on error.
##
function strtol(base)
{
  local_var s, i, place, result;

  if (max_index(_FCT_ANON_ARGS) != 1)
    return 0;

  s = _FCT_ANON_ARGS[0];
  if (!is_string(s) || s == "")
    return 0;

  if (isnull(base))
    base = 10;

  if (base < 2 || base > 36)
    return 0;

  place = 1;
  result = uint(0);
  for (i = strlen(s) - 1; i >= 0; i--)
  {
    result += from_digit(s[i]) * place;
    place *= base;
  }

  return result;
}

##
# Given an integer value, convert it to the corresponding string in the
# given base (default base 10).
#
# The most common bases are binary (2), octal (8), decimal (10), and
# hexadecimal (16). Any base up to 36 can be used, though, with a - z
# representing 10 - 35.
#
# This function got extremely complicated with edgecases, since the goal was
# to support everything that the printf suite of functions can do. In the end,
# it does, but has quite a few rare codepaths. Fortunately, all arguments
# are optional, so you don't need to use most of them for most cases.
#
# @remark Due to technical limitations, this overflows after 7 hex digits.
#
# @anonparam i           Integer to convert.
#
# @param base            Optional base. Default 10.
# @param leading_plus    Add a plus sign in front of positive numbers.
# @param leading_space   Add a space in front of positive numbers.
# @param left_justify    If set along with the width argument, will pad on the right instead of the left.
# @param lsb_first       The most significant bit/nibble/extra is first, rather than last. Default: FALSE.
# @param precision       If set, it pads the string to at least that size using either zeroes or the appropriate sign bit.
# @param prepend         If set, prepend this value to the string (eg, "0x") before padding.
# @param twos_complement If set, take the two's complement of negative values rather than simply prepending a minus sign. Only works for base 2, 8, and 16.
# @param width           The total width of the field (will pad with spaces).
# @param ucase           If set, return an uppercase digit.
#
# @return A string representing the value.
##
function ltostr(base, leading_plus, leading_space, left_justify, lsb_first, precision, prepend, twos_complement, width, ucase)
{
  local_var b, i, is_negative, j, s, m, type;

  i = _FCT_ANON_ARGS[0];
  if (isnull(i))
    return "";

  type = typeof(i);
  if (type != "int" && type != "uint")
    return "";

  # Set the default precision to zero.
  if (isnull(precision))
    precision = 0;

  # Set the default base to decimal.
  if (isnull(base))
    base = 10;

  if (base < 2 || base > 36)
    return "";

  # Handle two's complement -1 special. As the only value where
  # (~value - 1) is negative, it requires special treatment.
  s = "";
  if (twos_complement == TRUE && i == -1)
  {
    is_negative = TRUE;

    if (base == 2)
      s = "1";
    else if (base == 8)
      s = "";
    else if (base == 16)
      s = "";
    else
      # This is undefined for other bases.
      return "";
  }
  else
  {
    # Handle negative values
    if (i < 0)
    {
      is_negative = TRUE;
      if (twos_complement)
      {
        # Loop through all the bits from the left to the right, clearing them.
        # When we either get to the far right, or reach a 0 bit, we stop.
        for (j = 31; j >= 0 && ((i & 1 << j) != 0); j--)
          i = i & ~(1 << j);

        # Now, we have a string that starts with a 0. Because it's a
        # negative number, we now have to add the sign bit(s) back to
        # the number.
        if (base == 2)
        {
          # In binary, we simply set the left-most bit.
          i = i | (1 << ++j);
        }
        else if (base == 8)
        {
          # In octal, we set '1' bits until we reach a multiple of 3
          # bits (the length of a digit in octal).
          while (++j % 3 != 0)
            i = i | (1 << j);
        }
        else if (base == 16)
        {
          # In hexadecimal, we set '1' bits until we reach a multiple
          # of 4 bits (the length of a digit in hex).
          while (++j % 4 != 0)
            i = i | (1 << j);
        }
      }
      else
      {
        # If we aren't doing two's complement, just invert the number
        # (we add the minus sign later)
        i *= -1;
      }
    }

    # At this point, 'i' is a positive number that we can convert into
    # the proper base. We worry about adding the sign and stuff back
    # later. Now we use a standard algorithm to convert the number to
    # the appropriate base.
    s = "";
    for (j = 31; j >= 0; j--)
    {
      # Calculate the multiplier, and check for an overflow and skip
      # over it.
      m = base ** j;
      if (m == 0)
        continue;

      # Extract the next bit.
      b = i / m;

      # Remove that bit from the integer.
      i %= m;

      # If the bit is '0' and the string is blank, don't add it.
      if (b == 0 && s == "")
        continue;

      b = to_digit(b, base:base, ucase:ucase);
      if (lsb_first)
        s = b + s;
      else
        s = s + b;
    }

    # If the string was blank, consider it to mean zero.
    if (s == "")
      s = "0";
  }

  # Format negative values properly.
  if (is_negative)
  {
    # If it's two's complement, pad it with sign bits.
    if (twos_complement)
    {
      if (base == 2)
      {
        # Pad with '1's, as needed.
        s = lpad(s, precision, char:"1");
      }
      else if (base == 8)
      {
        # Pad with at least one '7', then more if needed.
        s = "7" + s;
        s = lpad(s, precision, char:'7');
      }
      else if (base == 16)
      {
        # Pad with at least one 'f', then more if needed.
        s = "f" + s;
        s = lpad(s, precision, char:"f");
      }
      else
      {
        # This is undefined for other bases.
        return "";
      }

      # If no precision is given, prepend '..', which represents an
      # infinite number of the first character.
      if (!precision)
        s = ".." + s;
    }
    else
    {
      # If it's negative and not two's complement, prepend a minus
      # sign (it's already an absolute value)
      s = "-" + lpad(s, precision, char:"0");
    }
  }
  else
  {
    # For positive values, lower the precision if we're added a plus
    # or a space
    if (width == 0)
    {
      if (leading_plus)
        precision--;
      if (leading_space)
        precision--;
    }

    # If we're prepending something (e.g., '0x', '0b', or '0'), remove
    # that much from the precision
    if (!isnull(prepend))
      precision -= strlen(prepend);

    if (lsb_first)
      s = rpad(s, precision, char:"0");
    else
      s = lpad(s, precision, char:"0");

    if (leading_plus)
      s = "+" + s;
    if (leading_space)
      s = " " + s;
  }

  # Prepend the appropriate data, if necessary.
  if (!isnull(prepend))
    s = prepend + s;

  # Pad the data to the requested width, if necessary.
  if (!isnull(width))
  {
    if (left_justify)
      s = rpad(s, width);
    else
      s = lpad(s, width);
  }

  return s;
}

##
# Convert a byte - between 0 and 255 - into the corresponding hex
# representation.
#
# @anonparam b The byte to convert.
# @param ucase If set to TRUE, return the hex in uppercase.
# @param lsn_first If set to TRUE, put the least significant nibble first.
#
# @return A 2-character hex string.
##
function byte_to_hex(ucase, lsn_first)
{
  local_var b, n1, n2;

  b = int(_FCT_ANON_ARGS[0]);

  # Grab the first two nibbles
  n1 = to_digit((b & 0xF0) >> 4, ucase:ucase);
  n2 = to_digit((b & 0x0F) >> 0, ucase:ucase);

  if (lsn_first)
    return n2 + n1;

  return n1 + n2;
}

##
# Pads a string on the left side to the given length.
#
# @anonparam s The string to pad.
# @anonparam length The desired length.
#
# @param char The character for padding; optional. Default: space.
#
# @return The string padded to the proper length.
##
function lpad(char)
{
  local_var len, pad, s;

  if (max_index(_FCT_ANON_ARGS) != 2)
    return "";

  s = _FCT_ANON_ARGS[0];
  if (!is_string(s))
    return "";

  len = int(_FCT_ANON_ARGS[1]);
  if (len <= 0 || strlen(s) >= len)
    return s;

  if (isnull(char))
    char = " ";

  return crap(data:char, length:len - strlen(s)) + s;
}

##
# Pads a string on the right side to the given length.
#
# @anonparam s The string to pad.
# @anonparam length The desired length.
#
# @param char The character for padding; optional. Default: space.
#
# @return The string padded to the proper length.
##
function rpad(char)
{
  local_var len, pad, s;

  if (max_index(_FCT_ANON_ARGS) != 2)
    return "";

  s = _FCT_ANON_ARGS[0];
  if (!is_string(s))
    return "";

  len = int(_FCT_ANON_ARGS[1]);
  if (len <= 0 || strlen(s) >= len)
    return s;

  if (isnull(char))
    char = " ";

  return s + crap(data:char, length:len - strlen(s));
}

##
# Masks a string with '*' char.
#
# @param  string string      String to mask.
# @param  int    mask_length OPTIONAL length of masking. If 0, then
#                            len(input) = len(output). Defaults to 6.
#
# @return string masked, NULL on error.
##
function mask_string(string, mask_length)
{
  # Accept string anonymously.
  if (isnull(string)) string = _FCT_ANON_ARGS[0];
  if (isnull(string))
  {
    err_print("mask_string(): missing required arg 'string'");
    return NULL;
  }

  if (isnull(mask_length)) mask_length = 6;
  else if (mask_length == 0) mask_length = len(string) - 2;
  else if (mask_length < 0)
  {
    err_print("mask_string(): arg mask_length must be nonnegative");
    return NULL;
  }

  return string[0] + crap(data:'*', length:mask_length)+ string[len(string) - 1];
}

##
# Convert bytes to GUID
#
# @param [bytes: data] byte string
#
# @return Returns a string formatted GUID, else NULL if a GUID could not be decoded from the supplied data
#
##
function bytes_to_formatted_guid(bytes)
{
  if (strlen(bytes) != 16) return NULL;

  var data1 = substr(bytes, 0, 3); # First 4 Bytes
  var data2 = substr(bytes, 4, 5); # Next 2 Bytes
  var data3 = substr(bytes, 6, 7); # Next 2 Bytes
  var data4 = substr(bytes, 8, 9); # Next 2 Btyes
  var data5 = substr(bytes, 10);   # Last 6 Bytes

  # Switch to Little Endien
  data1 = string_reverse(data1);
  data2 = string_reverse(data2);
  data3 = string_reverse(data3);
  # Data4 and data5 are actually 8 individual sections of 1 Byte each
  # Technically they should also be converted to Little Endien, but since they're all 1 Byte each, they're already
  # in the correct order as it is!

  var formatted_guid = strcat(hexstr(data1), '-', hexstr(data2), '-', hexstr(data3) , '-',  hexstr(data4), '-', hexstr(data5));

  return formatted_guid;
}
