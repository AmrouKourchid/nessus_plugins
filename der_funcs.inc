#TRUSTED b07bed3f8456bda289aacbb27f3f255dfceff9ce77571572d9b6732e8f92d76a3fcf5d7bff637c60a997b6d6189bb6f67b6a33d0792988e5b330b11d76349949ffa861f5e3b01acd97f7bcbee047a9e26f39ec75a4632543b9ba5a5bd2f4f734f5cb1b66335f730f7441c4f847f961cef15d17c4ef78049e959c8524149ca63dbf1b359683eac3b34f23c2c6bed81940b0ee611dbb6e0e1c80362224d3b27f63261d9ed28664d06bd1d7433e97fe196ac109da03cdad665097c693eed487540833932e8479175e9ea062444d85ba9cb733ed154951aff5115cd5a31e983fbe109a10d9741bef350386ce565782c1d7d464c6c21c267c72913877e7afe7d6640e6b832ababc9c667d8e3e5034105ce26e32c6f553afe4e927c95b7795b61409060e0c489589fffdb925ca279fc45d7aa34459fbeecd36d7b3b06b2d38d6dfae5852aa1990db861011b86f30ddf0657009ed0b4fb2d105024d8258fc4325964d1891b45aaccfa7234b2b829b7ff506811b646567e79f2a9a5054f3271432c785784a016856c12a13f9ffcacffd2e85783fd47487444ad581a84c2f67d1711b5822e5c0c888d958cbcd44437692708c4bc991d9a19321e3bfd7c6a97983a25393c833682ae0770cf86bb43b9176f96824ca13fcc7aad3323ce10597ac113807c3a748f5ad651c71b247946fc7066444011250dc5e9cc7044f9d074ab337b4478d5c
#TRUST-RSA-SHA256 927e588057e2782dcd1ae81a6cdc8a230075db46a3885e3748c0662517a868f9a1e13b230e9e766fd8486cf3c86a282a915959b24912bd61ac10bae762aba4814e298430b8279f88fadd52574ad36e75739247c843d1c928d9026cca40d02e564e71215ecc7c29b7f623ad5ecb65c77e9bea05e6aa4da04b4ea5685c5880bd8bf30924bd0beb696bc272d9d9525b34214dc97c27402ba71baf6643a11a2c153044318c887db712e531e8067392242cab5e91203ec44f107c242ccc5de1e50464acee20e683197dbe81ba36ee808d03bd9bf20c7120da2e40b7eb149c7edcde15929ca8db7542cdbc822764ec7dfcb3b79ff0faacdbda20fc06790ed71b3629340aa0e50dc15932979933757e39abf403ede2957163f88e937bc547c1bf9e28af93d543f9bf6163d9daf97fb810450c7cd452e949341440b7a3a9084091b8b31f8e9d321134b3f333232fdb8a2e09416fa65c4a9e1dc0e506da072ae3365e1cc0b4f6508b40d545b5e29596c74c2f4d2057b0ae93fca5d5f6679eb5e52a9c4b9486857dad08a07497b0807734d937596a8cb3e7c3d0556c5fe58d3013c55a286750aa7edf707c66d2d9fa4e7e9c3e7474dcf1283553e35919832ce6a4a961cf58d2eeb06823a4c46ff15ef9142e1aa1cbe7670020533e67f06ad2c33241d08a2c48d4ee118237d081c77562057099808bc9058337cf2bd98ce9d6760542390281
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
# Revision: 1.5

# BER tags
                                              # Int  Cl T Number
global_var BER_BOOLEAN_TAG            = 0x01; #   1  00 0 00001
global_var BER_INTEGER_TAG            = 0x02; #   2  00 0 00010 
global_var BER_BIT_STRING             = 0x03; #   3  00 0 00011 
global_var BER_OCTET_STRING           = 0x04; #   4  00 0 00100 
global_var BER_NULL                   = 0x05; #   5  00 0 00101 
global_var BER_OID_TAG                = 0x06; #   6  00 0 00110 
global_var BER_ENUMERATED_TAG         = 0x0a; #  10  00 0 01010 
global_var BER_IA5STRING_TAG          = 0x16; #  22  00 0 10110 
global_var BER_GENERAL_TIME_TAG       = 0x18; #  24  00 0 11000 
global_var BER_GENERAL_STRING_TAG     = 0x1b; #  27  00 0 11011 
global_var BER_BMP_STRING_TAG         = 0x1e; #  30  00 0 11110 
global_var BER_SEQUENCE_TAG           = 0x30; #  16  00 1 10000 <- Constructed Type  
global_var BER_STRING_SEQUENCE_TAG    = 0x31; #  17  00 1 10001 <- Is this meant to be SET?
global_var BER_AUTHENTICATION_TAG     = 0x80; #   0  10 0 00000 <- Context Specific, End of Content??? 
global_var BER_FILTER_TAG             = 0x87; #   7  10 0 00111 <- Context Specific, Object Descriptor???
global_var BER_IMPLICIT_DEF_SEQUENCE  = BER_SEQUENCE_TAG | 0x80000000; # 10 1 10000 <- Context Specific, Constructed, Sequence

include('string.inc');
include('debug.inc');

##
# Computes the DER encoded length of data.
#
# @param [data:string] The source data.
# @return Returns length of the data when DER encoded or 0.
##
function der_length(data)
{
  local_var tmp, length, len;

  length = NULL;
  len = strlen (data);

  if (len == 0)
    return raw_string(0);

  while (len != 0)
  {
    length = raw_string (len % 256) + length;
    len = len / 256;
  }

  if ((strlen (length) > 1) || ((strlen(length) == 1) && (ord(length[0]) > 127)))
    length = raw_string (128 + strlen (length)) + length;

  if (isnull(length))
    length = raw_string(0);

  return length;
}

##
# Given a DER field, determine how many significant bits it contains.
#
# This function is primarily for calculating the components of
# cryptographic parameters.
#
# @anonparam ds  A string, list, or array.
# @anonparam idx If ds is a list or array, any number of idx arguments
#                can be specified for indexing into ds to get a field.
#
# @return An integer indicating the the number of significant bits in
#         the the DER field, or NULL if there was an error.
##
function der_bit_length()
{
  local_var blob, byte, i, len, mask, max;

  # Sanity check parameters.
  max = max_index(_FCT_ANON_ARGS);
  if (max <= 0)
    return NULL;

  # Traverse data structure to get data.
  blob = _FCT_ANON_ARGS[0];
  for (i = 1; i < max; i++)
  {
    if (typeof(blob) != "array")
      return NULL;

    blob = blob[_FCT_ANON_ARGS[i]];
  }

  # We can only perform the calculation on text.
  if ((typeof(blob) !~ "^(data|string)$") || strlen(blob) <= 0)
    return NULL;

  # Calculate the key length. Keys are stored such that the modulus
  # always has leading zeros, but those zeros do not contribute to the
  # key length.
  byte = ord(blob[0]);
  len = strlen(blob);

  # A leading NUL byte indicates that the key's bit length is a
  # multiple of 8.
  if (byte == 0)
    return (len - 1) * 8;

  # If there is no leading NUL byte, we know that the key's length is
  # not a multiple of 8. This tends to be a bug in the algorithm that
  # generated the key. Remove the leading zeros to determine the
  # actual length of the key.
  len *= 8;

  for (mask = 0x80; mask > 0x00; mask >>= 1)
  {
    # Stop shrinking the key length once we see the most significant
    # bit.
    if (byte & mask)
      break;

    len--;
  }

  return len;
}


##
# DER encode the supplied data based on the provided tag
#
# @param [tag:integer]        A DER/BER enumerated type code.
# @param [data:byte sequence] The data to be encoded.
#
# @return Returns the DER encoded data.
##
function der_encode(tag, data)
{
  if (isnull(data) && tag != BER_NULL)
    return NULL;

  return raw_string (tag) + der_length(data:data) + data;
}


##
# Takes a string and converts it to a string of Hex representations of each char.
# Used for representing DER encoded data more easily
#
# @param  [data:data] A string to be converted
# @param  [int:length]  If provided, the function will only convert the first "length" chars of the string
#
# @return [string]      A string of hexadecimal representations of the chars in the original string
#                       The string will be empty if there were no chars to convert
##
function data2hexstr(data, length)
{
  local_var output, i;
  output = '';

  if (isnull(data))
    return output;

  if (isnull(length))
    length = strlen(data);

  for (i=0; i<length; i++)
  {
    if (i > 0) output += ' ';
    output += hexstr(data[i]);
  }

  return output;
}

##
# Given a blob of DER encoded data, decode and break down the Tag and Length data
#
# @param  [data:data]   A string of DER encoded data
#
# @return [array|NULL]  Returns an Array structure containg info about the Tag and Length of the DER data, or
#                       NULL if it was unable to decode
##
function der_decode_metadata(data)
{
  local_var tag, tag_data, tag_buf, tag_octets;
  local_var length, length_data, long_octs, length_octets;

  # If no data was provided or the first char is NULL
  if (isnull(data) || isnull(data[0]))
    return NULL;

  # First, Parse the Tag data

  tag = data[0]; # Start with the first Octet

  # Break the tag down to binary so we can fully parse it
  # Format: Class Type  Number
  #           00   0    00000
  tag_buf = ltostr(base:2, width:8, precision:8, ord(tag));

  tag_data = {
    'raw':    tag,                    # The "Raw" tag char from the given data blob
    'hex':    hexstr(tag),            # Hex representation of the entire Tag Octet
    'class':  substr(tag_buf, 0, 1),  # Class   (in Binary)
    'type':   tag_buf[2],             # Type    (in Binary)
    'number': substr(tag_buf, 3)};    # Number  (in Binary) If the Tag is in Short form, this represents the actual tag
                                      # If the Tag turns out to be in Long form, this will equal '11111'

  # Int representation of the Tag Number
  tag_data['id'] = int(strtol(base:2, tag_data.number));

  # Keep track of how many Octets make up the Tag
  tag_octets = 1;

  if (tag_data.number == '11111') # tag is in long form
  {
    tag_data['long'] = ''; # We'll buld this by getting subsequent Octets until the end of the Tag is reached
    repeat
    {
      # If we know the Tag is in Long Form, but we don't have another Octet to get...
      if (isnull(data[tag_octets]))
        return NULL;

      tag = data[tag_octets]; # Grab the next Octet
      tag_data.hex += ' '+hexstr(tag); # Store the hex for the new octet

      tag_buf = ltostr(base:2, width:8, precision:8, ord(tag)); # break the octet down to binary

      tag_data.long += substr(tag_buf, 1); # grab bits 6-0 and concat them with what we have so far

      tag_octets++;

    } until(tag_buf[0] == '0'); # bit 7 being 0 indicates that this is the last Tag Octet

    # Update the int ID with the fully constructed Long Tag
    tag_data['id'] = int(strtol(base:2, tag_data.long));
  }


  # Next, we Parse the Length

  # If there aren't any Octets after the last Tag Octet...
  if (isnull(data[tag_octets]))
    return NULL;

  length = data[tag_octets];

  length_data = {
    'raw':    length,             # "raw" Length Octet from the data blob
    'hex':    hexstr(length),     # Hex representation of the Length Octet(s)
    'as_int': integer(i:length)}; # Int representation of the Length

  # Keep track of how many Octets make up the Length
  length_octets = 1;

  if (length_data.as_int > 127) # Length is in Long-Form
  {
    # Number of additional Octets to describe length
    long_octs = length_data.as_int -= 128;

    # if we somehow don't have enough remaining octets to get the full length...
    if (tag_octets + length_octets + long_octs > strlen(data))
      return NULL;

    # Example
    # tag_octets = 3
    # length_length = 4
    # [tag, tag, tag, length, length, length, length, length, data, data, data, ...]

    # Get the rest of the Length octets
    length_data['long'] = substr(data, tag_octets + length_octets, tag_octets + length_octets + long_octs - 1);
    length_data.hex += ' '+data2hexstr(data:length_data.long);

    length_octets += long_octs;

    length_data.as_int = integer(i:length_data.long);
  }

  return {
    'tag':        tag_data,
    'length':     length_data,
    'data_start': tag_octets + length_octets, # Index at which the contents of the DER data starts
    'data_end':   tag_octets + length_octets + length_data.as_int}; # The Index at which the contents of the DER data ends
}


##
# Given a blob of DER encoded data, convert it to a more readable format for displaying
#
# @param  [data:data] A string of DER encoded data
# @param  [tab:int]   How many tabs to prepend to the formatted data (used for SEQUENCES)
#
# @return [string]  Returns the DER data formatted into a string
#
##
function display_der(data, tab)
{
  local_var output, i, tag, length, hex_length, value, seq_val, elem;

  if (isnull(tab) || tab <= 0)
    tab = 0;

  if (isnull(data))
    return 'No Data';

  local_var spacing = '';
  for (i=0; i<tab; i++)
    spacing += '  ';

  # Get the Metadata for the current der element
  local_var metadata = der_decode_metadata(data:data);
  if (isnull(metadata))
    return 'Unable to parse data as der';

  output = spacing+'['+metadata.tag.hex+']['+metadata.length.hex+']';

  if (metadata.data_end > strlen(data))
    return output += ':[Not enough data to decode full value]';

  if (metadata.length.as_int <= 0)
    output += ':[]';
  else
  {
    value = substr(data, metadata.data_start, metadata.data_end-1);

    # if the Type is a Sequnce (or a constructed App specific list of some sort)
    if (metadata.tag.id == 16 || ord(metadata.tag.raw) == 0xa0 || ord(metadata.tag.raw) == 0x31)
      output += ':[\n'+display_der(data:value, tab:tab+1)+'\n'+spacing+']';
    else
      output += ':['+data2hexstr(data:value)+']';
  }

  if (metadata.data_end < strlen(data)) # We have more data to parse
  {
    data = substr(data, metadata.data_end);
    output += '\n'+display_der(data:data, tab:tab);
  }
  # else no more data to parse!

  return output;
}


##
# Converts an string encoded integer into a native integer.
#
# @param [i:string] A string representing an integer.
#
# @return Returns the integer value of i.
##
function integer(i)
{
  local_var j,k;

  j = 0;

  for (k=0; k < strlen(i); k++)
  {
    j = j * 256 + ord(i[k]);
  }

  return j;
}

##
# DER encodes an OID string - ex: "1.2.840.113554.1.2.2"
#
# @param [oid:string] The OID encoded as a human readable string
#
# @return Returns a DER encoded byte sequence corresponding to the input.
##
function der_encode_oid(oid)
{
  local_var nums, num, enum, i, max, encoded;

  if (isnull(oid))
    return NULL;

  nums = split (oid, sep:".", keep:0);

  max = max_index (nums);
  if (max < 2)
    return NULL;

  # value1 x 40 + value2
  encoded = raw_string (40*int(nums[0]) + int(nums[1]));

  for (i=2; i < max; i++)
  {
    num = int(nums[i]);
    enum = raw_string (num % 128);
    num = num / 128;
    while (num != 0)
    {
      enum = raw_string (128 + (num%128)) + enum;
      num = num / 128;
    }
    encoded += enum;
  }

  return der_encode(tag:BER_OID_TAG, data:encoded);
}

##
# Decodes a DER encoded OID byte sequence into a human readable string
#
# @param [oid:byte sequence] The DER encoded OID
#
# @return Returns a human readable string corresponding to the
#         input DER encoded OID - ex: "1.2.840.113554.1.2.2"
##
function der_decode_oid(oid)
{
  local_var soid, i, val;

  if (strlen (oid) < 1)
    return NULL;

  soid = (ord (oid[0]) / 40) + "." + (ord (oid[0]) % 40);

  for (i = 1; i < strlen(oid); i++)
  {
    val = 0;
    while (ord(oid[i]) >= 128)
    {
      val = ((ord(oid[i]) - 128) + val) * 128;
      i++;
    }
    val += ord (oid[i]);
    soid += "." + val;
  }

  return soid;
}


##
# DER encode an integer value.
#
# @param [i:integer] The integer to encode.
#
# @return Returns a DER encoded integer.
# @remark This only correctly encodes 16-bit integers.
##
function der_encode_int(i)
{
  local_var val,j,tmp;

  if (isnull(i))
    return NULL;

  val[0] = i & 255;
  val[1] = (i>>8)  & 255;

  j = 3;
  while ((val[j] == 0) && (j != 0))
    j--;

  tmp = NULL;
  while (j != 0)
  {
    tmp += raw_string (val[j]);
    j--;
  }

  tmp += raw_string (val[j]);

  return der_encode(tag:BER_INTEGER_TAG, data:tmp);
}


##
# DER encode a 32-bit integer value.
#
# @param [i:integer] The integer to encode.
#
# @return Returns a DER encoded integer.
##
function der_encode_int32(i)
{
  local_var tmp;

  if (isnull(i))
    return NULL;

  tmp = raw_string ((i>>24) & 255,
                    (i>>16) & 255,
                    (i>>8)  & 255,
                    i & 255);

  return der_encode(tag:BER_INTEGER_TAG, data:tmp);
}


##
# DER encodes a string value.
#
# @param [string:string] The string to encode
#
# @return Returns a DER encoded string.
##
function der_encode_string(string)
{
  if (isnull(string))
    return NULL;

  return der_encode(tag:BER_GENERAL_STRING_TAG, data:string);
}


##
# DER encode a sequence of values.
#
# @param [seq:list] A sequence of DER encoded values.
#
# @return Returns a byte sequence representing a DER encoding of
#         input value.
##
function der_encode_sequence(seq)
{
  local_var encoded, max, i, j, val;

  if (isnull(seq))
    return NULL;

  max = max_index (seq);
  if (max == 0)
    return NULL;

  i = 0xA0;

  encoded = NULL;

  for (j=0; j < max; j++)
  {
    val = seq[j];
    if (!isnull(val))
    {
      encoded += der_encode(tag:i, data:val);
    }
    i++;
  }

  return der_encode(tag:BER_SEQUENCE_TAG, data:encoded);
}


##
# DER encodes an X509 generalized time string.
#
# @param [time:string] A time string in the format YYYYMMDDHHMMSSZ
#
# @return Returns a DER encoding of the time string.
# @remark Generalized times are defined in ietf RFC2580
#         https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.5.2
##
function der_encode_time(time)
{
  if (isnull(time))
    return NULL;

  return der_encode(tag:BER_GENERAL_TIME_TAG, data:time);
}


##
# Parses the first(outer) layer a blob of DER encoded data.
#
# @param [tag:integer]        Expected BER type code.
# @param [data:byte sequence] The DER blob to decode.
#
# @result Returns a representation of the input data with the
#         outer layer decoded.
##
function der_parse_data(tag, data)
{
  local_var tmp;

  tmp = der_decode(data:data);

  if (isnull(tmp) || (tmp[0] != tag))
    return NULL;

  return tmp[1];
}


##
# Parses a list of DER encoded items into a list of decoded
# items with the number of decoded items as the first element.
#
# @param [list:list] A list of DER encoded blobs.
#
# @return Returns a list of decoded items with the number of
#         decoded items as the first element.
##
function der_parse_list(list)
{
  local_var tmp,pos,i,ret;

  if (isnull(list))
    return NULL;

  tmp = NULL;
  tmp[0] = 0;

  if (strlen(list) <= 0)
  {
    tmp[0] = 0;
    return tmp;
  }

  pos = 0;
  i = 1;

  while (pos < strlen(list))
  {
    ret = der_decode(data:list,pos:pos);
    if (isnull(ret))
      return NULL;

    if (ret[0] == 0)
      tmp[i] = '';
    else
      tmp[i] = substr (list, pos, ret[2]-1);

    tmp[0] = tmp[0] + 1;
    pos = ret[2];
    i++;
  }

  return tmp;
}


##
# Parse a DER encoded sequence of items into a list of decoded
# items optionally preceded by the number of decoded items.
#
# @param [seq: byte sequence] A DER encoded sequence.
# @param [num: integer]       Length of the result list (optional).
# @param [list: boolean]      Indicates whether to return the number of
#                             decoded items in the first element of the result.
#
# @return Returns a list of decoded data.
##
function der_parse_sequence(seq, num, list)
{
  local_var tmp, dseq, val, i, pos, ret;

  dseq = der_decode(data:seq);
  if(isnull(dseq) || (dseq[0] != BER_SEQUENCE_TAG))
    return NULL;

  if(!isnull(list) && (list == TRUE))
    return der_parse_list(list:dseq[1]);

  tmp = NULL;
  for(i=0; i < num; i++)
    tmp[i] = NULL;

  pos = i = 0;
  while(pos < strlen(dseq[1]))
  {
    ret = der_decode(data:dseq[1], pos:pos);
    if(isnull(ret))
      return NULL;

    val = ret[0] - 0xA0;
    if(val < 0)
      return NULL;

    tmp[val] = ret[1];
    pos = ret[2];
  }

  return tmp;
}


##
# Decode a DER encoded blob.
#
# @param [data: byte sequence] The DER encoded data to decode.
# @param [pos: integer]        Position within the data to start decoding.
# @param [sloppy: boolean]     Returns results on error if TRUE.
#
# @return Returns a list with the BER type code, decoded data and
#         the position in the encoded data right after the decoded
#         element.
##
function der_decode(data, pos, sloppy)
{
  local_var tmp, i, j, len, len2;

  if (isnull(data))
    return NULL;

  if (isnull(pos))
    j = 0;
  else
    j = pos;

  if (j < 0 || strlen(data) - j  < 2)
    return NULL;

  tmp[0] = ord(data[j]);
  j++;

  len = ord(data[j]);
  j++;

  if (len > 127)
  {
    len -= 128;
    if (strlen(data) - j < len)
      return NULL;

    len2 = integer (i:substr (data, j, j + len - 1));
    j += len;
    len = len2;
  }

  # Special Case for if length is 0
  if (len == 0)
  {
    tmp[1] = '';
    tmp[2] = j + len;
    return tmp;
  }

  if (strlen(data) - j < len)
  {
    # Permit sloppy parsing, where if we're missing part of the body we
    # return what we do have.
    if (!sloppy)
      return NULL;
    len = strlen(data) - j;
  }

  tmp[1] = substr(data,j,j+len-1);
  tmp[2] = j + len;
  return tmp;
}


##
# Parses a DER encoded integer.
#
# @param [i:byte sequence] A DER encoded integer value.
#
# @return Returns the integer represented by the input data.
##
function der_parse_int(i)
{
  local_var tmp;

  tmp = der_parse_data(tag:BER_INTEGER_TAG, data:i);
  if (isnull(tmp))
    return NULL;

  tmp = integer (i:tmp);
  if (isnull(tmp))
    return NULL;

  return tmp;
}


##
# Parses a DER encoded boolean.
#
# @param [bool:byte sequence] A DER encoded boolean value.
#
# @return Returns the boolean represented by the input data.
##
function der_parse_bool(bool)
{
  local_var tmp;

  tmp = der_parse_data(tag:BER_BOOLEAN_TAG, data:bool);
  if (isnull(tmp))
    return NULL;

  tmp = integer(i:tmp);
  if (isnull(tmp))
    return NULL;

  if (tmp == 0)
    tmp = FALSE;
  else
    tmp = TRUE;

  return tmp;
}


##
# Parses a DER encoded octet string (byte sequence).
#
# @param [string: byte sequence] A DER encoded octet.
#
# @return Returns a byte sequence represented by the input data.
##
function der_parse_octet_string(string)
{
  return der_parse_data(tag:BER_OCTET_STRING, data:string);
}

##
# Parses a DER encoded BMP string. (basic multilingual plane)
#
# @param [bmpString:bytes] A DER encoded BMP string.
#
# @return Returns the BMP string represented by the input.
# @remark BMP strings place the codepage in the first byte
#         of a 2-byte character encoding.
##
function der_parse_bmp_string(bmpString)
{
  return der_parse_data(tag:BER_BMP_STRING_TAG, data:bmpString);
}


##
# Parses a DER encoded OID.
#
# @param [oid: byte sequence] A DER encoded OID.
#
# @return Returns the encoded OID as a string.
##
function der_parse_oid(oid)
{
  local_var tmp;

  tmp = der_parse_data(tag:BER_OID_TAG, data:oid);
  if (!tmp)
    return NULL;

  tmp = der_decode_oid(oid:tmp);
  if (!tmp)
    return NULL;

  return tmp;
}


##
# Parse a DER encoded sequence of OIDs
#
# @param [list: byte sequence] The DER encoded OID list
#
# @return Returns a list of human readable OID strings.
##
function der_parse_list_oid(list)
{
  local_var tmp, seq, i;

  tmp = NULL;

  seq = der_parse_sequence(seq:list, list:TRUE);
  if (isnull(seq))
    return NULL;

  for (i=0;i < seq[0];i++)
  {
    tmp += der_parse_oid(oid:seq[i+1]) + " ";
  }

  return tmp;
}


##
# Parse a DER encoded sequence of strings into a list of decoded
# strings optionally preceded by the number of decoded items.
#
# @param [seq: byte sequence] A DER encoded sequence.
# @param [num: integer]       Length of the result list (optional).
# @param [list: boolean]      Indicates whether to return the number of
#                             decoded strings in the first element of the result.
#
# @return Returns a list of decoded strings.
##
function der_parse_set(set, num, list)
{
  local_var tmp, dset, val, i, pos, ret;

  dset = der_decode(data:set);
  if(isnull(dset) || (dset[0] != BER_STRING_SEQUENCE_TAG))
    return NULL;

  if(!isnull(list) && (list == TRUE))
    return der_parse_list(list:dset[1]);

  tmp = NULL;
  for(i=0; i < num; i++)
    tmp[i] = NULL;

  pos = i = 0;
  while(pos < strlen(dset[1]))
  {
    ret = der_decode(data:dset[1],pos:pos);
    if (isnull(ret))
      return NULL;

    val = ret[0] - 0xA0;
    if (val < 0)
      return NULL;

    tmp[val] = ret [1];
    pos = ret[2];
  }

  return tmp;
}


##
# DER encode a byte sequence (octet string).
#
# @param [string: byte sequence] Byte sequence to encode.
#
# @return Returns a DER encoded octet string.
##
function der_encode_octet_string(string)
{
  return der_encode(tag:BER_OCTET_STRING, data:string);
}


##
# DER encode a list.
#
# @param [list:list] The list to encode.
#
# @return Returns a DER encoded list.
##
function der_encode_list(list)
{
  return der_encode(tag:BER_SEQUENCE_TAG, data:list);
}


##
# Encode an integer as a DER enumerated value.
#
# @param [e:integer] An enumerated value
#
# @returns A DER encoded enumerated value.
##
function der_encode_enumerated(e)
{
  local_var val, j, tmp;

  if (isnull(e))
    return NULL;

  val[0] = e & 255;
  val[1] = (e >> 8) & 255;

  j = 3;
  while ((val[j] == 0) && (j != 0))
    j--;

  tmp = NULL;
  while (j != 0)
  {
    tmp += raw_string(val[j]);
    j--;
  }

  tmp += raw_string(val[j]);


  return der_encode(tag:BER_ENUMERATED_TAG, data:tmp);
}


##
# DER encoded a boolean value.
#
# @param [b:boolean] The boolean to encode
#
# @return Returns a DER encoded boolean value.
##
function der_encode_boolean(b)
{
  if(isnull(b))
    return NULL;

  return der_encode(tag:BER_BOOLEAN_TAG, data:raw_string(b));
}


##
# DER encodes a filter string.
#
# @param [code: integer]  A BER type code.
# @param [filter: string] The string to encode.
#
# @return Returns a DER encoded filter
##
function der_encode_filter(code, filter)
{
  if (isnull(code))
    code = BER_FILTER_TAG;

  return der_encode(tag:code, data:filter);
}

##
# Parse a DER encodede GUID
# https://learn.microsoft.com/en-us/dotnet/api/system.guid.tobytearray?view=net-7.0#examples
#
# @param [data: data]  DER encoded byte string
#
# @return Returns a string formatted GUID
#         Returns NULL if a GUID could not be decoded from the supplied data
##
function der_parse_GUID(data)
{
  var guid_bytes;

  guid_bytes = der_parse_octet_string(string:data);
  return bytes_to_formatted_guid(bytes:guid_bytes);
}
