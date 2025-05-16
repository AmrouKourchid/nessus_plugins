#TRUSTED 68d1910ba4ba68952aef84ccb57dbc05651f89f263dc4f10a867cb01f7efb0d6de5880ac5acda788b714c46831589f467abb89258bfd01046391d3d2b819c8fb692837ee4801dc6a62ba3d1c0bf1761085fb33346cc2e9816fc44e5f5b0a7008bc62f33b9c8b0da5b61bcc97b4b1741c72a912a0a5f46a840bfff287a639697fd2d7a6b80045e968158e0b461db1c4c2d354bf4248a0cc7a4d2de06c787449321c50d1aa46031290deeb060046faaa9f2a99bad4722e087899d90c09fb381f179d2fccb9eb16a42ac31b3eec9fff645307d7c52147f32982d12400187aef8fb82fee15e61ba21f8bf0169ab2d90d8fbbfef6df5be49df1ab6eb4aa5d63cb8a4e8ce14612eb0f946de8953bd417a41f1fc7feb52370460d8646341a03d9b4285099d94e7cf2238c2b7c8426d062cf89ed291258aa5064c7b598a436a2b1a1c0e6eff779d4cee8788fdc0fbe25ea78e889dcda1e1c839b4cca3a821c040b3aa0908f64e62297f6a3cc8d5fad87a70db37a3921791d7b8b4a9eee0a5066ee6f09cfa3dd407a0dba6d744b9e7a79e449edde6c528b802c5278040db18a24a9493eb2ab1a63a3d4a7e7fae0acc249227ae554bae5273b959c369290496430d011e4ca0f7c070b75e0ce6a83705c926e8ce1e2d8eef767125516f7a181701797f52bdbeed1892e2b16eba39735ef0e27047fbfb026907e64719b333893e57c024a5967
#TRUST-RSA-SHA256 738106fd888fe923ae6719125ab96a9fdeaa72c4ea961a4ed2e6331f855b430f347b2faf9600e9f5b6807cc369cc2d7275a000a51ab27441b54b899443732f7b230a3b9016dc5797e142bc3b94dd564ee22fc529ecf60b10f704f25ca23010678f16f1e28969eabb01e76498667fdff9ba3e7aca639222f0a32fd4c4865db610273c89953e4b12ca7e26a2a8cfa3adf8ed0bfb6433ced96c8510133bfa263c6bc72032e1199694e1a812e46802a9b721ec2fbe4ec1a23694c6ea1b10839dc56d00ebf791f09f1874b9bb6242cedee1795b69ff80a7a05cedd43f053733842aeff8e326fbcd1fbb6d740d9bb9e39f81ad7ece26a34f2f5a6c144a68861cd6bef84d2daa6dce7f19e1b97da6995be6bee507eec598df6149c3652b343a87db1e89a57f8ab373ac864b8e332b588b1ab40fb3e3da1b39874885aff622ba24df3f2625f7da682713c7f9c2803e7253c54b853ffc4b28732596786e8ff6f227765cea27437f487f6bad8ca78f66fb93b835e80dcf5a48d2008af435c680f95eec297f11c7e1bed86ae2324d363c4f4f602ae0857c7033cff414b7cd9fb03ef624d351fb43ece0b33277eec9cd1550520e54308d779aaf1e485a84fa67894694c98f9165f6a7903f5ed8de64b884b9a658018aaff6d5c0136c80f7224b1c2573de720f0cda081799fb4e5086bfc481d371af7f40a825dee630e3f5ef7409eccf51ce4c
include("compat_shared.inc");
include('string.inc');
include('der_funcs.inc');
include('x509_func.inc');
include('debug.inc');


# Blob Properties
global_var BLOB_KEY_PROV_INFO                 = 2;  # 02 00 00 00
global_var BLOB_SHA1_HASH                     = 3;  # 03 00 00 00
global_var BLOB_MD5_HASH                      = 4;  # 04 00 00 00
global_var BLOB_KEY_SPEC                      = 6;  # 06 00 00 00 
global_var BLOB_ENHKEY_USAGE                  = 9;  # 09 00 00 00 
global_var BLOB_FRIENDLY_NAME                 = 11; # 0B 00 00 00 
global_var BLOB_DESCRIPTION                   = 13; # 0D 00 00 00 
global_var BLOB_SIGNATURE_HASH                = 15; # 0F 00 00 00 
global_var BLOB_KEY_IDENTIFIER                = 20; # 14 00 00 00 
global_var BLOB_AUTO_ENROLL                   = 21; # 15 00 00 00 
global_var BLOB_PUBKEY_ALG_PARA               = 22; # 16 00 00 00 
global_var BLOB_ISSUER_PUBLIC_KEY_MD5_HASH    = 24; # 18 00 00 00 
global_var BLOB_SUBJECT_PUBLIC_KEY_MD5_HASH   = 25; # 19 00 00 00 
global_var BLOB_DATE_STAMP                    = 27; # 1B 00 00 00 
global_var BLOB_ISSUER_SERIAL_NUMBER_MD5_HASH = 28; # 1C 00 00 00 
global_var BLOB_SUBJECT_NAME_MD5_HASH         = 29; # 1D 00 00 00 
global_var BLOB_CERT                          = 32; # 20 00 00 00

global_var blob_property_lookup = make_array(
  BLOB_KEY_PROV_INFO,                 'KEY_PROV_INFO',
  BLOB_SHA1_HASH,                     'SHA1_HASH',
  BLOB_MD5_HASH,                      'MD5_HASH',
  BLOB_KEY_SPEC,                      'KEY_SPEC',
  BLOB_ENHKEY_USAGE,                  'ENHKEY_USAGE',
  BLOB_FRIENDLY_NAME,                 'FRIENDLY_NAME',
  BLOB_DESCRIPTION,                   'DESCRIPTION',
  BLOB_SIGNATURE_HASH,                'SIGNATURE_HASH',
  BLOB_KEY_IDENTIFIER,                'KEY_IDENTIFIER',
  BLOB_AUTO_ENROLL,                   'AUTO_ENROLL',
  BLOB_PUBKEY_ALG_PARA,               'PUBKEY_ALG_PARA',
  BLOB_ISSUER_PUBLIC_KEY_MD5_HASH,    'ISSUER_PUBLIC_KEY_MD5_HASH',
  BLOB_SUBJECT_PUBLIC_KEY_MD5_HASH,   'SUBJECT_PUBLIC_KEY_MD5_HASH',
  BLOB_DATE_STAMP,                    'DATE_STAMP',
  BLOB_ISSUER_SERIAL_NUMBER_MD5_HASH, 'ISSUER_SERIAL_NUMBER_MD5_HASH',
  BLOB_SUBJECT_NAME_MD5_HASH,         'SUBJECT_NAME_MD5_HASH',
  BLOB_CERT,                          'CERT'
);

##
# Given a Microsoft Serialized Blob of data, parse out the properties within and return them
#
# @param  [data:byte sequence] The data to be parsed
#
# @return Returns a list of of properties in the form of [ID, Value, Next]
#         or NULL if no properties were able to be parsed
##

function parse_serialized_blob(data)
{
  var i = 0;
  var props = [];
  var prop;

  if (empty_or_null(data))
    return NULL;

  while (!empty_or_null(data))
  {
    prop = decode_serialized_property(data:data);
    if (prop == NULL)
    {
      dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:'Unable to Decode Serialized Property');
      return NULL;
    }

    # Save the Propertie
    props[i] = prop;

    # shift the data to start at the next property
    data = substr(data, prop[2]);
    i++;
  }

  dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:'Parsed '+max_index(props)+' Serialized Properties');

  if (empty_or_null(props))
    return NULL;

  return props;
}

##
# Given a byte sequence, decode the serialized property it represents
#
# @param  [data:byte sequence] The data to be decoded
#
# @return Returns an list in the format of [Property ID, Property Value, Next Property Index]
#         or NULL if the data was unable to be decoded as a serialized peroperty
##

function decode_serialized_property(data)
{
  var prop_id, prop_name, reserved, length, value;

  # Serialized Property Format:
  # [00 00 00 00] [01 00 00 00] [00 00 00 00] [...]
  # Property ID   Encoding ASN.1  Length        Value

  # If we don't have enought octets for a full TLV, bail
  if (strlen(data) < 12)
    return NULL;

  prop_id = substr(data, 0, 3);   # First 4 Octets are the Property ID
  reserved = substr(data, 4, 7);  # Next 4 Octets are Reserved (But might also denote encoding for the value??)
  length = substr(data, 8, 11);   # Last 4 Octets are the Length

  # if reserved is not 01 00 00 00, either this isn't a serialized TLV, or the value is not ASN.1 encoded
  if (hexstr(reserved) != '01000000')
  {
    dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:'Serialized Property is not ASN.1 Encoded');
    return NULL;
  }

  dbg::detailed_log(lvl:2, src:FUNCTION_NAME,
    msg:'Serialized TLV: ['+data2hexstr(data:prop_id)+']['+data2hexstr(data:reserved)+']['+data2hexstr(data:length)+']');

  # Reverse Byte order for Little Endian
  prop_id = string_reverse(prop_id);
  length = string_reverse(length);

  # Convert to Int
  prop_id = integer(i:prop_id);
  length = integer(i:length);

  # And grab the value!
  if (strlen(data)-12 < length)
  {
    dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:'Serialized Property Value is incomplete/missing');
    return NULL;
  }

  value = substr(data, 12, 11+length);

  prop_name = blob_property_lookup[prop_id];
  if (empty_or_null(prop_name)) prop_name = prop_id;

  dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:'Property: '+prop_name+'  Length: '+length);

  switch (prop_id)
  {
    # case  BLOB_KEY_PROV_INFO:
    case  BLOB_SHA1_HASH:
      value = hexstr(value);
      break;
    case  BLOB_MD5_HASH:
      value = hexstr(value);
      break;
    case  BLOB_KEY_SPEC:
      value = string_reverse(value); # convert to Little Endian
      value = integer(i:value);
      break;
    # case  BLOB_ENHKEY_USAGE:
    case  BLOB_FRIENDLY_NAME:
      value = str_replace(find:raw_string(0), replace:"", string:value);
      break;
    case  BLOB_DESCRIPTION:
      value = str_replace(find:raw_string(0), replace:"", string:value);
      break;
    case  BLOB_SIGNATURE_HASH:
      value = hexstr(value);
      break;
    case  BLOB_KEY_IDENTIFIER:
      value = hexstr(value);
      break;
    case  BLOB_AUTO_ENROLL:
      value = str_replace(find:raw_string(0), replace:"", string:value);
      break;
    # case  BLOB_PUBKEY_ALG_PARA:
    case  BLOB_ISSUER_PUBLIC_KEY_MD5_HASH:
      value = hexstr(value);
      break;
    case  BLOB_SUBJECT_PUBLIC_KEY_MD5_HASH:
      value = hexstr(value);
      break;
    case  BLOB_DATE_STAMP:
      value = string_reverse(value);
      value = integer(i:value);
      break;
    case  BLOB_ISSUER_SERIAL_NUMBER_MD5_HASH:
      value = hexstr(value);
      break;
    case  BLOB_SUBJECT_NAME_MD5_HASH:
      value = hexstr(value);
      break;
    case  BLOB_CERT:
      value = parse_der_cert(cert:value);
      break;
    default:
      value = hexstr(value);
      break;
  }


  return [prop_name, value, length+12];
}

