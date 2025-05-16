#TRUSTED 09a2ad24eb576db9436765b05703860e3479167253689e763f22404838941ed3cfa8532424c86f52fa9c03d5be9b3245b16f0af37b9f0388b88754e7a5584046a897780813aee95d5d72fb19829b8744e155c928005d006a7dcc6e30f0c159a4fff3419c2804cd6d8b81a39253557427e402ce63001f5d6243a303ba447b484efe5fd029f550e64935bc3db2f76c86008f8f54660a5d3f256786fa51f58f83ee78c66c1a5606d046b8ef73be6da4b2100aca033a4c19ef61dacfe52e39195d58a3e3b085771a37daaafacf321e09b9305ab56650971d7776601ab7478df126df6efdb1a3a02fc08b2323cf7ae31dcc9a8169ce793aa8377658c491cb226c02681d01c719ac46c8d1472eef3fdb6d48817c01f53a6d42325b562452330bdbf042979cd8188becae6626785ae3f4d1bae410cfab1a71863e7835ec43296c6a4af061e52d0a7e584309d68f8987785ac0030560114bf8e2bc71bbcbd4c201df7747ec009fab9b1ef3104c641671cb73170f69d3e7cdd7da990456c4532ba8b9506d7ed56305c48f2564ccc492396de29e3c652e85bf0e7bb9c9f00cacc951978cc5aa346b1f4b852969bb2e6a874c9784e0307e58f2f8b700a495e3a4817ef319e08dd6fd388ec7d93d5926a191cea82add239b1d8e6ba91036cf51509b8bf739333b7e06e30960d0601d667c11c872f94cd67a9b1dd3354d248943d6c8af3b2d3a
#TRUST-RSA-SHA256 332baa646fbb95230522d9829473153f8fc8ac0ec9c2134079ec0a333ccd3f5e813a1ce28e5ce936807fc098014c029fd54a73d166f403375b394fe46a06db15336ffc6b9a90c4aca3e8b47f8e58e136e59d92866fb798dbdf7b7a74b6ec0f1eaab86e124065187db07dfbafceaa115a233f0d9671f55a34b8177a86a030fabc0aaa0a0bb8c905fa0d72532643d0d0ec21ddd2155a93e9161a41d6aec736a9cdebbb241d518056239f718288f1236d84276d21ab22bdb3e3592451f1cb5ff4b7392e0dc46d6960e9f62e3bef42ef72b21e8f235f7b40edeaf1da2b670d67cba86b23583ffe830322544ca78509e0fa4272340b9180702ace6bc7e486a81aac9d5a32265616a330b8abfdb0f10123a3f15782a86b4af684b9d9f5517ae93ce4bf187e5dbb9dfbd1faf47ebd2dce903c3abbb7bd3128ba5ca15abd22737db345029f5112e94d548464ae080cf79e7ebd746e7a85ada96c1aa5d9b85fe821629826f07b22d5575a11225e58ae14fa3890962f4b7198a7d555ceea533e942da67829e56276dc2dc239da351c87847d3695705e8a2dd5340f2ebf1cca0060747bf3e7d7a12ce6f18dc101afbe1fa673cf975607d2cc51da0c42663147d603588369626ec880d29763b35dd692012599203865fbd59fdb7aea79e8c2b73e0b82436e021dcb1a6997734098f21c691a66677135b79fbb7bee39ac7a176be9b531ef1146
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# snmp_func.inc
# Revision: 1.44
#

include("compat_shared.inc");
include("ssh_globals.inc");
include("byte_func.inc");
include("crypto_func.inc");
include("lcx.inc");
include("debug.inc");
include("der_funcs.inc");

global_var snmp_request_id, SNMP_VERSION, end_mib;
global_var msg_id, auth_engine_id, auth_engine_boots, auth_engine_time;

global_var creds, snmpv3_auth, snmpv3_priv;

snmp_request_id = rand();       # Should not be predictable
end_mib = FALSE;

auth_engine_id    = '';
auth_engine_boots = 0;
auth_engine_time  = 0;
creds = make_list( '', '', '', '', '', '' );
snmpv3_auth = NULL;
snmpv3_priv = NULL;

SNMP_VERSION = get_kb_item ("SNMP/version");
global_var _SNMP_VERSION = NULL;
if (isnull(SNMP_VERSION))
  SNMP_VERSION = 0; # snmpv1

##
# Sets end_mib global to false
#
# @return NULL
# @category SNMP
##
function init_snmp ()
{
  end_mib = FALSE;
}

global_var MSG_MAX_SIZE = 4096;

global_var MSG_AUTHENTICATED_FLAG  = 0x01;
global_var MSG_ENCRYPTED_FLAG      = 0x02;
global_var MSG_REPORTABLE_FLAG     = 0x04;

global_var USM_SECURITY_MODEL = 0x03;

global_var PEPPER = rand();  # to be loaded at boot as per rfc3414, section 8.1.1.1.1

# Fake out a 64 bit random number by picking an outer random 32 bit and packing it backwards.
set_byte_order( BYTE_ORDER_LITTLE_ENDIAN );
global_var PEPP64 = mkdword( rand() );  # for faking a 64 bit random number
set_byte_order( BYTE_ORDER_BIG_ENDIAN );

global_var USM_LEVEL_AUTH_PRIV       = 0x03;   # authPriv
global_var USM_LEVEL_AUTH_NO_PRIV    = 0x01;   # authNoPriv
global_var USM_LEVEL_NO_AUTH_NO_PRIV = 0x00;   # noAuthNoPriv

global_var OP_GET_REQUEST      = 0xa0;
global_var OP_GET_NEXT_REQUEST = 0xa1;
global_var OP_SET_REQUEST      = 0xa3;
global_var OP_GET_BULK_REQUEST = 0xa5;

global_var TYPE_INTEGER = 0x02;
global_var TYPE_OCTET_STRING = 0x04;
global_var TYPE_NULL = 0x05;

global_var SYS_DESCR = '1.3.6.1.2.1.1.1.0';

global_var USM_STATS_NOT_IN_TIME_WINDOW  = '1.3.6.1.6.3.15.1.1.2.0';
global_var USM_STATS_UNKNOWN_USER_NAMES  = '1.3.6.1.6.3.15.1.1.3.0';
global_var USM_STATS_UNKNOWN_ENGINE_IDS  = '1.3.6.1.6.3.15.1.1.4.0';
global_var USM_STATS_WRONG_DIGESTS       = '1.3.6.1.6.3.15.1.1.5.0';
global_var USM_STATS_DECRYPTION_ERRORS   = '1.3.6.1.6.3.15.1.1.6.0';

#https://tools.ietf.org/html/rfc1905
#section 3
global_var SNMP_ERRORSTATUS_NOERROR = 0;
global_var SNMP_ERRORSTATUS_NOACCESS = 6;
global_var SNMP_ERRORSTATUS_AUTHORIZATIONERROR = 16;

global_var AUTH_ALGORITHMS = {
  'MD5': {
    'engine': @MD5,
    'hmac': @HMAC_MD5,
    'truncate': 12
  },
  'SHA1': {
    'engine': @SHA1,
    'hmac': @HMAC_SHA1,
    'truncate': 12
  },
  'SHA-224': {
    'engine': @SHA224,
    'hmac': @HMAC_SHA224,
    'truncate': 16
  },
  'SHA-256': {
    'engine': @SHA256,
    'hmac': @HMAC_SHA256,
    'truncate': 24
  },
  'SHA-384': {
    'engine': @SHA384,
    'hmac': @HMAC_SHA384,
    'truncate': 32
  },
  'SHA-512': {
    'engine': @SHA512,
    'hmac': @HMAC_SHA512,
    'truncate': 48
  }
};


##
# Renders an integer in ber encoding
#
# @param <i> String host name or ip address of the remote SSH server
# @return NULL if i is NULL, else return ber encoded integer
# @category SNMP
##
function ber_put_int (i)
{
  var val,j,tmp;

  if (isnull (i))
    return NULL;

  val[0] = i & 255;
  val[1] = (i>>8)  & 255;
  val[2] = (i>>16) & 255;
  val[3] = (i>>24) & 255;

  j = 3;
  while ((val[j] == 0) && (j != 0) && (val[j-1] < 0x80))
    j--;

  tmp = NULL;

  while (j != 0)
  {
    tmp += raw_string (val[j]);
    j--;
  }

  tmp += raw_string (val[j]);

  return der_encode (tag:BER_INTEGER_TAG, data:tmp);
}

##
# Renders a string in ber octet string encoding
#
# @param <string> String to encode
# @return BER_OCTET_STRING encoded string
# @category SNMP
##
function ber_put_octet_string (string)
{
  if(isnull(string))
    string = "";
  return der_encode (tag:BER_OCTET_STRING, data:string);
}


##
# Renders a pdu in ber encoded GetRequestPDU
#
# @param <pdu> String to encode
# @return OP_GET_REQUEST encoded pdu
# @category SNMP
##
function ber_put_get_pdu (pdu)
{
  return der_encode (tag:OP_GET_REQUEST, data:pdu);
}


##
# Renders a pdu in ber encoded GetRequestNextPDU
#
# @param <pdu> String to encode
# @return OP_GET_NEXT_REQUEST encoded pdu
# @category SNMP
##
function ber_put_get_next_pdu (pdu)
{
  return der_encode (tag:OP_GET_NEXT_REQUEST, data:pdu);
}


##
# Renders a pdu in ber encoded SetRequestPDU
#
# @param <pdu> String to encode
# @return OP_SET_REQUEST encoded pdu
# @category SNMP
##
function ber_put_set_pdu (pdu)
{
  return der_encode (tag:OP_SET_REQUEST, data:pdu);
}

##
# Renders a pdu in ber encoded GetRequestNextPDU
#
# @param <pdu> String to encode
# @return OP_GET_NEXT_REQUEST encoded pdu
# @category SNMP
##
function ber_put_get_bulk_pdu (pdu)
{
  return der_encode (tag:OP_GET_BULK_REQUEST, data:pdu);
}

##
# Renders a null in ber encoding
#
# @return BER_NULL encoded
# @category SNMP
##
function ber_put_null ()
{
  return der_encode (tag:BER_NULL, data:NULL);
}


##
# Renders an oid in ber encoded BER_OID_TAG
#
# @param <oid> String to encode, example: "1.2.840.113554.1.2.2"
# @return NULL if oid is empty, NULL, or doesn't have enough sections, else
#         BER_OID_TAG encoded oid
# @category SNMP
##
function ber_put_oid (oid)
{
  var nums, num, enum, i, max, encoded;

  if (isnull (oid))
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

  # OID Tag = 0x06
  return der_encode (tag:BER_OID_TAG, data:encoded);
}


##
# Renders a squence in ber encoded BER_SQUENCE_TAG
#
# @param <seq> String to encode
# @return BER_SEQUENCE_TAG encoded seq
# @category SNMP
##
function ber_put_sequence (seq)
{
  var encoded, max, i, j, val;

  max = max_index (seq);

  encoded = NULL;

  for (j=0; j < max; j++)
  {
    val = seq[j];
    if (!isnull(val))
    {
      encoded += val;
    }
  }

  return der_encode (tag:BER_SEQUENCE_TAG, data:encoded);
}

##
# Attempts to parse an integer from a string
#
# @param <i> String to parse
# @return Integer encoding
# @category SNMP
##
function _integer (i)
{
  var j,k,len;

  j = 0;
  len = strlen (i);

  for (k=0; k < len; k++)
  {
    j = j * 256 + ord(i[k]);
  }

  return j;
}



##
# Decodes a block of ber data
#
# @param <data> Data to encode
# @param <pos> Optional byte to begin at
# @return NULL if data is NULL or not enough data available at pos, else
#         a list containing the starting pos, the data, and the next pos in the buffer
# @category SNMP
##
function ber_decode (data, pos)
{
  var tmp, i, j, len, len2;

  if (isnull (data))
    return NULL;

  if (isnull (pos))
    j = 0;
  else
    j = pos;

  if (strlen(data) - j  < 2)
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

    len2 = _integer (i:substr (data, j, j + len - 1));
    j += len;
    len = len2;
  }

  if (strlen(data) - j < len)
    return NULL;

  tmp[1] = substr(data,j,j+len-1);
  tmp[2] = j + len;

  # tmp is a tuple of 3 elements ( the starting index position, the read value, and the total length)
  return tmp;
}


##
# Decodes an encoded BER_OID_TAG as an oid string
#
# @param <oid> BER_OID_TAG to encode
# @return NULL if oid is empty, NULL, or doesn't have enough sections, else
#         oid encoded BER_OID_TAG, example: "1.2.840.113554.1.2.2"
# @category SNMP
##
function ber_decode_oid (oid)
{
  var soid, i, val, len;

  if (strlen (oid) < 1)
    return NULL;

  soid = ord(oid[0]) / 40 + "." + ord(oid[0]) % 40;

  len = strlen (oid);

  for (i = 1; i < len; i++)
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
# Decodes encoded ber data and checks if tag matches
#
# @param <tag> tag to match ber object with
# @param <data> ber data to decode
# @return NULL if ber_decode fails or tag doesn't match the returned tag, else
#         ber_decoded data
# @category SNMP
##
function ber_get_data (tag,data)
{
  var tmp;

  tmp = ber_decode (data:data);
  if (isnull (tmp) || (tmp[0] != tag))
    return NULL;

  return tmp[1];
}


##
# Decodes an encoded ber sequence
#
# @param <seq> ber encoded sequence
# @return NULL if seq is empty, NULL, or doesn't decode to a list whose tag is 0x30, else
#         NULL if any part of the sequence fails to ber decode, else
#         string format of the sequence
# @category SNMP
##
function ber_get_sequence (seq)
{
  var tmp,pos,i,ret,list, len;

  if (!seq)
    return NULL;

  list = ber_decode (data:seq);

  if (isnull(list) || (list[0] != 0x30))
    return NULL;

  list = list[1];

  tmp = NULL;
  tmp[0] = 0;

  pos = 0;
  i = 1;
  len = strlen (list);

  while (pos < len)
  {
    ret = ber_decode (data:list,pos:pos);
    if (isnull(ret))
      return NULL;

    ##### NOTE, this was tmp[i] = substr (list, pos, ret[2]), which led to duplication of the last character in the str
    tmp[i] = substr (list, pos, ret[2] - 1);
    tmp[0] = tmp[0] + 1;
    pos = ret[2];
    i++;
  }

  # tmp[ 0 ] is the count of the number of elements in tmp
  return tmp;
}


##
# Decodes an encoded ber response_pdu
#
# @param <pdu> ber pdu to decode
# @return NULL if pdu is falsy or doesn't match pdu tags, else
#         ber decoded response_pdu in string form
# @category SNMP
##
function ber_get_response_pdu (pdu)
{
  var tmp,pos,i,ret,list, len;

  if (!pdu)
    return NULL;

  list = ber_decode (data:pdu);
  # 0xA1 = SNMPv1 get next request
  # 0xA2 = SNMPv1 get response
  # 0xA8 = SNMPv3 report
  if (isnull(list) || ((list[0] != 0xA2) && (list[0] != 0xA1) && (list[0] != 0xA8)) )
    return NULL;

  list = list[1];

  tmp = NULL;
  tmp[0] = 0;

  pos = 0;
  i = 1;
  len = strlen (list);

  while (pos < len)
  {
    ret = ber_decode (data:list,pos:pos);
    if (isnull(ret))
      return NULL;

    #### POSSIBLE SAME ISSUE AS IN ber_get_sequence
    tmp[i] = substr (list, pos, ret[2] - 1);
    tmp[0] = tmp[0] + 1;
    pos = ret[2];
    i++;
  }

  return tmp;
}


##
# Decodes an encoded ber int
#
# @param <i> ber int to decode
# @return NULL if i doesn't decode as an int tagged ber value, else
#         NULL if i doesn't convert with _integer(), else
#         ber decoded int
# @category SNMP
##
function ber_get_int (i)
{
  var tmp;

  tmp = ber_get_data (tag:0x02, data:i);
  if (isnull(tmp))
    return NULL;

  tmp = _integer (i:tmp);
  if (isnull(tmp))
    return NULL;

  return tmp;
}

##
# Decodes an encoded ber address
#
# @param <i> ber address to decode
# @return NULL if i doesn't decode as an address tagged ber value or is the wrong size, else
#         ber decoded address
# @category SNMP
##
function ber_get_addr (i)
{
  var tmp;

  tmp = ber_get_data (tag:0x40, data:i);
  if (isnull(tmp) || strlen(tmp) != 4)
    return NULL;

  return ord(tmp[0]) + '.' + ord(tmp[1]) + '.' + ord(tmp[2]) + '.' + ord(tmp[3]);
}


##
# Decodes an encoded ber counter32
#
# @param <i> ber counter32 to decode
# @return NULL if i doesn't decode as a counter32 tagged ber value, else
#         NULL if i doesn't decode properly with _integer(), else
#         ber decoded counter32
# @category SNMP
##

function ber_get_counter32 (i)
{
  var tmp;

  tmp = ber_get_data (tag:0x41, data:i);
  if (isnull(tmp))
    return NULL;

  tmp = _integer (i:tmp);
  if (isnull(tmp))
    return NULL;

  if (tmp < 0) {tmp += 2147483648; }
  return tmp;
}


##
# Decodes an encoded ber time
#
# @param <time> ber time to decode
# @return NULL if i doesn't decode as a time tagged ber value or is the wrong size or too big, else
#         ber decoded time as string
# @category SNMP
##
function ber_get_timeticks (time)
{
  var tmp, ms, ss, mm, hh, dd;

  tmp = ber_get_data (tag:0x43, data:time);
  if (isnull(tmp))
    return NULL;

  if ((strlen(tmp) > 4) || (strlen(tmp) == 4 && ord(tmp[0]) > 0x80))
  {
    return "Time is too big to be decoded : 0x" + hexstr(tmp) + " ms";
  }

  tmp = _integer (i:tmp);
  if (isnull(tmp))
    return NULL;

  # convert to sec
  tmp = tmp / 1000;
  ss = tmp % 60;
  tmp = tmp / 60;
  mm = tmp % 60;
  tmp = tmp / 60;
  hh = tmp % 24;
  dd = tmp / 24;

  return dd + "d " + hh + "h " + mm + "m " + ss + "s";
}


##
# Decodes an encoded ber octet string
#
# @param <string> ber octet string to decode
# @return NULL if i doesn't decode as an octet string tagged ber value, else
#         ber decoded octet string
# @category SNMP
##
function ber_get_octet_string (string)
{
  return ber_get_data (tag:0x04, data:string);
}


##
# Decodes an encoded ber oid
#
# @param <oid> ber oid to decode
# @return NULL if i doesn't decode as an oid tagged ber value or fails to decode an oid, else
#         ber decoded oid
# @category SNMP
##
function ber_get_oid (oid)
{
  var tmp;

  tmp = ber_get_data (tag:0x06, data:oid);
  if (!tmp)
    return NULL;

  tmp = ber_decode_oid (oid:tmp);
  if (!tmp)
    return NULL;

  return tmp;
}

##
# Sends SNMP data and awaits a reply
#
# @param <socket> connection to send across
# @param <data> data to send
# @param <timeout> seconds to wait for reply
# @param <ret_err> value to return if error encountered
# @return value of snmp_reply() for these args
# @category SNMP
##
function snmp_exchange( socket, data, timeout, ret_err )
{
  send( socket:socket, data:data );
  return snmp_reply( socket:socket, timeout:timeout, ret_err:ret_err );
}

##
# Marks an SNMPv3 attempt as failed
#
# @param <reason> The reason for the failure
# @return NULL
# @category SNMP
##
function snmpv3_fail( reason )
{
  dbg::detailed_log(lvl:1, src:SCRIPT_NAME, name:'snmp_func', msg:
    'SNMPv3 failed. Reason: ' + reason);

  # Do not permit a single failed SNMPv3 connection to thwart all future connections
  #set_kb_item( name:"SNMP/v3/FAILED", value:TRUE );
  return NULL;
}


##
# Logs a failed decode attempt along with the packet data
#
# @param <reason> The part of the decode that failed
# @param <packet> The packet which failed (optional)
# @return NULL
# @category SNMP
##
function snmp_fail_decode(reason, packet)
{
  var msg_details;
  if (!isnull(packet))
  {
    msg_details = {'Data': {'lvl': 3, 'value': packet}};
  }
  dbg::detailed_log(lvl:1, src:SCRIPT_NAME, name:'snmp_func',
                    msg:'SNMP packet decoding failed : ' + reason,
                    msg_details:msg_details);
  return NULL;
}


##
# Extracts an encoded ber reply value
#
# @param <rep> Response to exract
# @return NULL if rep is too short or signifies end or is unrecognized, else
#         appropriate ber decoding call based on the tag value
# @category SNMP
##
function snmp_extract_reply (rep)
{
  if (strlen(rep) < 2)
    return NULL;

  if (ord(rep[0]) == 0x02)
    return ber_get_int (i:rep);

  if (ord(rep[0]) == 0x40)
    return ber_get_addr(i: rep);

  if (ord(rep[0]) == 0x41)
    return ber_get_counter32 (i:rep);

  if (ord(rep[0]) == 0x04)
    return ber_get_octet_string (string:rep);

  if (ord(rep[0]) == 0x06)
    return ber_get_oid (oid:rep);

  if (ord(rep[0]) == 0x82)
  {
    end_mib = TRUE;
    return NULL;
  }

  if (ord(rep[0]) == 0x43)
    return ber_get_timeticks (time:rep);

  return NULL;
}


##
# Parses SNMPv3 header data
#
# @param <head_blob> Header to extract
# @return NULL if the parsed sequence start isn't 4, else
#         NULL if parsed msg_id doesn't match expected global stored value, else
#         NULL if the parsed security model isn't USM_SECURITY_MODEL
#         msg_flags
# @category SNMP
##
function snmpv3_parse_header( head_blob )
{
  var head_seq, _msg_id, msg_flags, msg_sec_model;

  head_seq = ber_get_sequence( seq:head_blob );

  if  ( head_seq[ 0 ] != 4 )
    return NULL;

  _msg_id       = ber_get_int( i:head_seq [ 1 ] );
  msg_flags     = ber_get_octet_string( string:head_seq[ 3 ] );
  msg_sec_model = ber_get_int( i:head_seq [ 4 ] );

  if ( ( _msg_id != msg_id ) || ( msg_sec_model != USM_SECURITY_MODEL ))
    return NULL;
  return msg_flags;
}


##
# Parses SNMPv3 authoritative data
#
# @param <auth_blob> Authoritative data to extract
# @return NULL if the expected engine id or time or username don't match, else
#         NULL if we can't extract the engine boots, else
#         a list containing the authentication and privacy parameters
# @category SNMP
##
function snmpv3_parse_authoritative( auth_blob, msg_flags )
{
  var msg_auth_engine_id, msg_auth_engine_boots, msg_auth_engine_time;
  var msg_user_name, msg_authent_params, msg_privacy_params, ret, auth_data_seq;

  auth_data_seq = ber_get_sequence( seq:ber_get_octet_string( string:auth_blob ) );

  msg_auth_engine_id     = ber_get_octet_string( string:auth_data_seq [ 1 ] );
  msg_auth_engine_boots  = ber_get_int( i:auth_data_seq [ 2 ] );
  msg_auth_engine_time   = ber_get_int( i:auth_data_seq [ 3 ] );
  msg_user_name          = ber_get_octet_string( string:auth_data_seq [ 4 ] );
  msg_authent_params     = ber_get_octet_string( string:auth_data_seq [ 5 ] );
  msg_privacy_params     = ber_get_octet_string( string:auth_data_seq [ 6 ] );

  # If we don't have any part of this data, set it all.  Possibily redundent, probably always all or nothing.
  # http://www.ietf.org/rfc/rfc3414.txt Section 2.3
  if( ( ! auth_engine_id ) || ( ! auth_engine_boots  ) || ( !  auth_engine_time  ) )
  {
    auth_engine_id    = msg_auth_engine_id;
    auth_engine_boots = msg_auth_engine_boots;
    auth_engine_time  = msg_auth_engine_time;
  }
  else
  {
    # Breaking this into multiple comparisons for readability and clear commenting
    # If the engine IDs or boot counts don't match, this host has changed or rebooted during the scan.
    # If the time ticks decreased, then we may be seeing a replay or badly delayed packet.
    if  ( auth_engine_id != msg_auth_engine_id )
      return snmpv3_fail( reason:'engine_id' );
    else if ( auth_engine_boots != msg_auth_engine_boots )
      return snmpv3_fail( reason:'boots' );
    else if ( ( auth_engine_time - 150 > msg_auth_engine_time  ) || ( auth_engine_time + 150 < msg_auth_engine_time  ) )
      return snmpv3_fail( reason:'time' );  # RFC 3414, 3.7.a
  }

  # As the engine time and boots are used to calculate the IV for the privacy algorithm
  # they need to be updated when the agent responds with a reportable message
  if ((msg_flags | MSG_REPORTABLE_FLAG) && !isnull(msg_auth_engine_time))
  {
    auth_engine_boots = msg_auth_engine_boots;
    auth_engine_time = msg_auth_engine_time;
  }

  # RFC 3414, http://www.ietf.org/rfc/rfc3414.txt, Sec 3.2: check username, check auth, then decrypt
  # however, this function does not have visibility of the encrypted data or the whole message, so we check the
  # username and return the msg_authent_params and msg_privacy_params for evaluation elsewhere.
  if ( creds[ 0 ] != msg_user_name )
    return NULL;

  ret = make_list();
  ret[ 0 ] = msg_authent_params;
  ret[ 1 ] = msg_privacy_params;
  return ret;
}


##
# Returns ber decoded snmp reply value
#
# @param <socket> connection to receive from
# @param <timeout> seconds to wait for reply
# @param <ret_err> value to return if error encountered
# @return NULL if we fail to receive data correctly or can't decode directly, else
#         a list of oid, response, and if ret_err is set the error code if present
# @category SNMP
##
function snmp_reply (socket, timeout, ret_err)
{
  var seq, res, pdu, error, oid, ret, rep, id, cmpt, vers, tmp;
  var msg_flags, msg_auth_priv_params, response_data_index, decrypted, whole_msg, encrypted_pdu;
  var total_size, variable_bindings, ret_size, ret0, ret1, i, variable, inner_seq, auth_alg;

  cmpt = 5;

  # should we attempt to return a non-null value if an error code
  # other than 0 is received?
  if (isnull(ret_err) || !ret_err) ret_err = FALSE;
  else ret_err = TRUE;

  while (cmpt)
  {
    # Minimum prevents TCP sockets from timing out waiting for the full 4096 bytes.
    # The uses for SNMP over TCP are constrained to probing plugins which will only
    # see a header making it very unlikely that a message will be split over multiple
    # packets.
    rep = recv(socket:socket, length:4096, timeout:timeout, min:5);
    if (!rep)
    {
      dbg::detailed_log(lvl:2, src:SCRIPT_NAME + ':' + FUNCTION_NAME, name:'snmp_func', msg:'No packet received');
      return NULL;
    }
    total_size = strlen(rep);

    # First decode snmp reply (sequence)
    seq = ber_get_sequence (seq:rep);

    # seq[0] contains the number of elements in seq.
    # snmpv1/2c will have 3 parts (version, community string, body)
    # snmpv3 will have 4 parts(version, msg global data, auth data, body).
    if (isnull(seq) || ( (seq[0] != 3) && (seq[0] != 4) ))
      return snmp_fail_decode(reason:'could not extract top-level sequence', packet:rep);
    # Check if version is equal to the SNMP version.
    vers = ber_get_int (i:seq[1]);
    if (isnull(vers) || vers != SNMP_VERSION)
      return snmp_fail_decode(reason:'incorrect SNMP version');
    # If we're dealing with SNMPv1/2c, move right on to reading the response PDU from seq[3]
    # however, for SNMPv3, the auth data is in seq[3] and the response PDU is in seq[4]
    response_data_index = 3;
    if ( vers == 3 )
    {
      # Validate header data and return relevant information
      msg_flags = snmpv3_parse_header( head_blob:seq[ 2 ] );
      if  ( ! msg_flags )
        return snmp_fail_decode(reason:'could not retrieve message flags');

      # Handle SNMPv3 Authoritative Engine Data
      msg_auth_priv_params = snmpv3_parse_authoritative( auth_blob:seq[ 3 ], msg_flags:msg_flags );
      if  ( ! msg_auth_priv_params )
        # Reason already logged by parsing function
        return NULL;

      # If the packet is flagged as authenticated, check authentication.
      if  ( ord( msg_flags ) & MSG_AUTHENTICATED_FLAG )
      {
        auth_alg = AUTH_ALGORITHMS[creds[2]];
        if (isnull(auth_alg))
          return NULL;
        # Replace the auth params with N null bytes, as if we were preparing to send.
        whole_msg = str_replace( string:rep, find:msg_auth_priv_params[ 0 ], replace:auth_empty_string(alg:auth_alg), count:1 );
        # Get back the response with calculated auth params.
        whole_msg = snmpv3_authenticate_incoming( auth_passwd:snmpv3_auth, whole_msg:whole_msg, alg:auth_alg );
        # Compare the packed result with the received data
        if  ( whole_msg != rep )
        {
          dbg::detailed_log(lvl:1, src:SCRIPT_NAME + ':' + FUNCTION_NAME, name:'snmp_func', msg:'Return authentication failed');
          return NULL;
        }
        else if ( ord( msg_flags )& MSG_ENCRYPTED_FLAG )
        {
          encrypted_pdu = ber_get_octet_string( string:seq[ 4 ] );
          decrypted = snmpv3_decrypt_incoming(  msg_data:encrypted_pdu,
                                                priv_alg:creds[ 4 ],
                                                priv_param:msg_auth_priv_params[ 1 ] );
          if  ( ! decrypted )
          {
            dbg::detailed_log(lvl:1, src:SCRIPT_NAME + ':' + FUNCTION_NAME, name:'snmp_func', msg:'Decryption failed');
            return NULL;
          }
          # Replace the encrypted PDU with the decrypted one.
          seq[ 4 ] = decrypted;
        }
      }
      # Massage the returned PDU so that it can be parsed with the same process as SNMPv1/2c responses.
      response_data_index = 4;
      tmp = ber_get_sequence( seq:seq[ response_data_index ] );
      seq[ response_data_index ] = tmp[ 3 ];
    }

    # Check if Response PDU is 2
    pdu = ber_get_response_pdu( pdu:seq[ response_data_index ] );
    if (isnull(pdu) || (pdu[0] != 4))
      return snmp_fail_decode(reason:'incorrect PDU', packet:pdu);

    id = ber_get_int (i:pdu[1]);
    # ID will be zero when a decryption failure occurs.  The message should still be parsed.
    if ( !isnull(id) && ( ( id == (snmp_request_id - 1) ) || id == 0 ) )
    {
      # only continue if Error == NO ERROR, unless the caller has told us to do otherwise
      error = ber_get_int (i:pdu[2]);

      # store auth/auth problems for reporting
      if(error && (error == SNMP_ERRORSTATUS_NOACCESS || SNMP_ERRORSTATUS_AUTHORIZATIONERROR ))
        snmp_set_kb_auth_problem();

      if (isnull(error) || (error != SNMP_ERRORSTATUS_NOERROR && !ret_err))
        return snmp_fail_decode(reason:'server did not return a success error code', packet:rep);

      # Extract response
      seq = ber_get_sequence (seq:pdu[4]);
      if (isnull(seq))
        return snmp_fail_decode(reason:'no response PDU', packet:rep);;
      variable_bindings = seq[0];
      if ((variable_bindings > 1) && (variable_bindings == (max_index(seq) - 1)))
      {
        ret_size = 0;
        ret0 = make_list();
        ret1 = make_list();
        i = -1;
        foreach variable (seq)
        {
          if (i == -1)
          {
            i++;
            continue;
          }
          inner_seq = ber_get_sequence(seq:variable);
          ret0[i] = ber_get_oid(oid:inner_seq[1]);
          ret1[i] = snmp_extract_reply(rep:inner_seq[2]);
          i++;
        }
        ret = make_list2(ret0, ret1, 0, total_size);
        return ret;
      }

      seq = ber_get_sequence (seq:seq[1]);
      if (isnull(seq) || (seq[0] != 2))
        return snmp_fail_decode(reason:'incorrect sequence length in response', packet:rep);

      oid = ber_get_oid (oid:seq[1]);
      res = snmp_extract_reply (rep:seq[2]); # This appears to be reading the value incorrectly

      if (isnull(res))
        dbg::detailed_log(lvl:1, src:SCRIPT_NAME+':'+FUNCTION_NAME, name:'snmp_func',
                          msg:'Failed to decode response',
                          msg_details:{'Data': {'lvl':3, 'value':seq[2]}});
      if ( isnull( oid ) )
        return snmp_fail_decode(reason:'no OID');
      else if ( oid == USM_STATS_UNKNOWN_USER_NAMES )
        return snmpv3_fail( reason:'Unknown user.' );
      else if ( oid == USM_STATS_WRONG_DIGESTS )
        return snmpv3_fail( reason:'Authentication failure.' );
      else if ( oid == USM_STATS_DECRYPTION_ERRORS )
        return snmpv3_fail( reason:'Target side failed the decrypt of our request.' );
      else if ( oid == USM_STATS_NOT_IN_TIME_WINDOW )
        return snmpv3_fail( reason:'Could not synchronise time with target' );

      ret = make_list();
      ret[0] = oid;
      ret[1] = res;
      if (ret_err) ret[2] = error;

      return ret;
    }
    cmpt--;
  }
}


##
# Returns a list of several parsed connection details from globally stored values
#
# @return NULL the id, engine boots, or engine time fail to parse successfully, else
#         a list of id, engine boots, and engtime time
# @category SNMP
##
function snmp_put_engine_data()
{
  var id, boots, entime;
  id = ber_put_octet_string( string:auth_engine_id );
  boots = ber_put_int( i:auth_engine_boots );
  entime = ber_put_int( i:auth_engine_time );

  if(isnull(id) || isnull(boots) || isnull(entime))
    return NULL;

  return make_list( id, boots, entime );
}


##
# Assembles a ber sequence of the raw authoritative engine data
#
# @param <auth_engine_data> authentication engine data to supply
# @param <msg_user_name> user name to supply
# @param <msg_auth_param> authentication parameters to supply
# @param <msg_priv_param> privilege parameters to supply
# @return ber encoded sequence of the engine data, username, auth params, and priv params
# @category SNMP
##
function snmp_assemble_authentication_data( auth_engine_data, msg_user_name, msg_auth_param, msg_priv_param )
{
  var seq;

  msg_user_name = ber_put_octet_string( string:msg_user_name );
  msg_auth_param = ber_put_octet_string( string:string( msg_auth_param ) );
  msg_priv_param = ber_put_octet_string( string:string( msg_priv_param ) );
  if(isnull(msg_priv_param))
    msg_priv_param = "";
  if(isnull(msg_auth_param))
    msg_auth_param = "";
  if(isnull(msg_user_name))
    msg_user_name = "";
  if(isnull(auth_engine_data))
    auth_engine_data = "";
  seq = make_list( auth_engine_data, msg_user_name, msg_auth_param, msg_priv_param );

  return ber_put_octet_string( string:ber_put_sequence( seq:seq ) );
}


##
# Assembles a request payload
#
# @param <seq> sequence to send
# @param <op> operation to conduct
# @param <community> optional community string to use for older snmp prefixes
# @param <context_name> optional context_name string to use for newer snmp prefixes
# @param <non_repeaters> optional non repeaters flag to use for OP_GET_BULK_REQUEST operations
# @param <max_repetitions> optional max repetitions flag to use for OP_GET_BULK_REQUEST operations
# @remark This *should* work for v1 and v3 payloads, but has not been tested with v1.
# @return ber encoded sequence of the request payload
# @category SNMP
##
function snmp_assemble_request_data( seq, op, community, context_name, non_repeaters, max_repetitions )
{
  var request, request_prefix;

  if ( op == OP_GET_BULK_REQUEST )
  {
    request = ber_put_int( i:snmp_request_id )         + # Request ID
              ber_put_int( i:non_repeaters )           + # non-repeaters
              ber_put_int( i:max_repetitions )         + # max-repitions
              ber_put_sequence ( seq:make_list( seq ) ); # Object Identifier
  }
  else
  {
    request = ber_put_int( i:snmp_request_id )          + # Request Id
              ber_put_int( i:0 )                        + # Error Status: NO ERROR (0)
              ber_put_int( i:0 )                        + # Error Index (0)
              ber_put_sequence( seq:make_list( seq ) );   # Object Identifier
  }

  # Increment the request counter global.
  snmp_request_id += 1;

  # If using a community string based auth model, the first two arguments are SNMP version and the community string,
  # for USM (SNMPv3) auth the first two arguments are the context_engine_id and the context name.
  if ( SNMP_VERSION < 3 )
  {
    request_prefix =  ber_put_int( i:SNMP_VERSION ) +                       # v1 version
                      ber_put_octet_string( string:community );             # v1 community string
  }
  else if ( SNMP_VERSION == 3 )
  {
    request_prefix =  ber_put_octet_string( string:auth_engine_id ) +       # v3 contextEngineID
                      ber_put_octet_string( string:context_name );          # v3 optional contextName
  }

  if ( op == OP_GET_REQUEST  )
    request = request_prefix + ber_put_get_pdu( pdu:request );             # PDU type
  else if ( op == OP_GET_NEXT_REQUEST  )
    request = request_prefix + ber_put_get_next_pdu( pdu:request );        # PDU type
  else if ( op == OP_GET_BULK_REQUEST )
    request = request_prefix + ber_put_get_bulk_pdu( pdu:request );        # PDU type

  return ber_put_sequence( seq:make_list( request ) );
}

##
# Executes an empty SNMPv3 request to learn remote engine information
#
# @param <socket> connection to send data to
# @param <timeout> seconds to wait for reply
# @param <msg_global_data> previously assembled message global data
# @remark SNMPv3 uses authentication and privacy. It may attempt one or more logins here. It may or may not succeed.
# @return NULL if SNMP/v3/FAILED previously written, else
#         NULL if engine id unknown or NULL response, else
#         SNMP response
# @category SNMP
##
function snmpv3_initial_request( socket, msg_global_data, timeout )
{
  if( get_kb_item( "SNMP/v3/FAILED" ) )
    return NULL;

  var authentication_data, snmp_header, req, rep;

  # The initial request uses null auth data
  authentication_data = snmp_assemble_authentication_data(  auth_engine_data:snmp_put_engine_data(),
                                                            msg_user_name:'',
                                                            msg_auth_param:string( 0 ),
                                                            msg_priv_param:NULL );

  snmp_header = raw_string( ber_put_int( i:SNMP_VERSION ), msg_global_data, authentication_data );

  req = snmp_assemble_request_data( seq:make_list(), op:OP_GET_REQUEST );

  rep = snmp_exchange( socket:socket, data:( ber_put_sequence( seq:make_list( snmp_header, req ) ) ), timeout:timeout );

  if ( ( isnull(rep) ) || ( rep[ 0 ] != USM_STATS_UNKNOWN_ENGINE_IDS ) )
    return snmpv3_fail( reason:'response not unknown engine id' );
  else
  {
    replace_kb_item( name:'SNMP/v3/Supported', value:1 );
    return rep[1];
  }
}

##
# Assembles Global Message Data Values into a ber encoded sequence
#
# @param <msx_max_size> Maximum size value to send in sequence
# @param <msg_flags> Flags to send in sequence
# @param <msg_security_model> Security model to use in sequence
# @remark SNMPv3 uses authentication and privacy. It may attempt one or more logins here. It may or may not succeed.
# @return ber encoded message global data sequence
# @category SNMP
##
function snmpv3_put_msg_global_data( msg_max_size, msg_flags, msg_security_model )
{
  var seq;
  msg_id--;
  seq[0] = ber_put_int( i:msg_id );
  seq[1] = ber_put_int( i:msg_max_size );
  seq[2] = ber_put_octet_string( string:raw_string( msg_flags ) );
  seq[3] = ber_put_int( i:msg_security_model );
  return ber_put_sequence( seq:seq );
}

##
# Performs key localization as defined in RFC 3414.
#
# @param <passwd> Authentication Password to encode
# @param <alg> Algorithm to encode password with - entry of the AUTH_ALGORITHMS array
# @param <min_length> Optional integer indicating how long the returned key is required to be
# @param <cisco_extension> Boolean, if true then the Reeder (Cisco) password extension scheme is used
# @return algorithm encoded password
# @category SNMP
##
function password_to_key( passwd, alg, min_length, cisco_extension )
{
  var buffer, inter, key;

  buffer = crap( data:passwd, length:1048576 );

  inter = alg.engine(buffer);
  key = alg.engine(inter + auth_engine_id + inter);

  if (!isnull(min_length) && len(key) < min_length)
  {
     if (cisco_extension)
     {
       key += password_to_key(passwd:key, alg:alg, min_length:min_length-len(key), cisco_extension:TRUE);
     }
     else
     {
       while (len(key) < min_length)
       {
         key += alg.engine(key);
       }
     }
  }

  return key;
}


##
# XOR's each byte of two bitstrings
#
# @param <bitstring1> String to xor
# @param <bitstring2> String to xor
# @return NULL if string lengths aren't equal, else
#         raw string of each byte orded and XORed with the other string's byte
# @category SNMP
##
function XOR( bitstring1, bitstring2 )
{
  var len, i, ret_value;
  ret_value = '';
  len = strlen( bitstring1 );

  if  ( len != strlen( bitstring2 ) )
    return NULL;

  for ( i = 0; i < len; i++ )
    ret_value += raw_string( ord( bitstring1[ i ] ) ^ ord( bitstring2[ i ] ) );
  return ret_value;
}


##
# Return an empty string of the correct length for an authentication algorithm
#
# @param <alg> Algorithm in use
# @return NULL if algorithm unknown
#         raw string of zeros of the correct length for the algorithm
# @category SNMP
##
function auth_empty_string(alg)
{
  if (isnull(alg))
    return NULL;
  return crap(data:raw_string(0x00), length:alg.truncate);
}


##
# Performs RFC3414 usmHMAC*AuthProtocol for SNMPv3
#
# @param <auth_key> Key to authenticate
# @param <whole_msg> String to hash and place authentication string in
# @param <alg> Hashing algorithm used for authentication - entry of AUTH_ALGORITHMS
# @renark Consult section 7 of http://www.ietf.org/rfc/rfc3414.txt for details
# @return whole_msg with authentication for that string inserted in the auth space
# @category SNMP
##
function usm_HMAC_auth_protocol(auth_key, whole_msg, alg)
{
  var digest = alg.hmac(key:auth_key, data:whole_msg);
  var truncated = substr(digest, 0, alg.truncate-1);
  whole_msg =  str_replace( string:whole_msg, find:auth_empty_string(alg:alg), replace:truncated, count:1 );
  return whole_msg;

}

##
# Performs RFC3414's USM Incoming Message Authentication for SNMPv3
#
# @param <auth_passwd> Unused. Remove?
# @param <whole_msg> Message received
# @param <alg> Authentication Algorithm to perform
# @renark Consult section 3.1.8 of http://www.ietf.org/rfc/rfc3414.txt for details
# @return NULL if auth_key KB is missing or no recognized alg, else
#         alg-dependent authenticated version
# @category SNMP
##
function snmpv3_authenticate_incoming( auth_passwd, whole_msg, alg )
{
  var auth_key;
  auth_key = get_kb_item( 'Secret/SNMP/v3/LocalizedAuthKey' );
  if ( ! auth_key )
    return NULL;   # If we haven't stored the auth key, then this is not a response to a message we sent.
  else
    auth_key = base64_decode( str:auth_key );

  return usm_HMAC_auth_protocol(auth_key:auth_key, whole_msg:whole_msg, alg:alg);
}


##
# Performs RFC3414's USM Outgoing Message Authentication for SNMPv3
#
# @param <auth_passwd> Optional Password to authenticate with if not already in KB
# @param <whole_msg> Message to send
# @param <alg> Authentication Algorithm to perform
# @renark Consult section 3.1.8 of http://www.ietf.org/rfc/rfc3414.txt for details
# @return NULL if recognized alg, else
#         alg-dependent authenticated version
# @category SNMP
##
function snmpv3_authenticate_outgoing( auth_passwd, whole_msg, alg )
{
  var auth_key;
  auth_key = get_kb_item( 'Secret/SNMP/v3/LocalizedAuthKey' );
  if ( ! auth_key )
  {
    auth_key = password_to_key( passwd:auth_passwd, alg:alg );
    replace_kb_item( name:'Secret/SNMP/v3/LocalizedAuthKey', value:base64( str:auth_key ) );
  }
  else
    auth_key = base64_decode( str:auth_key );
  return usm_HMAC_auth_protocol(auth_key:auth_key, whole_msg:whole_msg, alg:alg);
}


##
# Performs RFC3414's AES privacy encryption for SNMPv3
#
# @param <priv_key> Privacy key to use
# @param <msg_data> Message to privacy encrypt
# @param <alg> AES algorithm being used, to calculate size to operate on
# @renark Consult section 3.3.1 of http://www.ietf.org/rfc/rfc3826.txt for details
# @return AES privatized msg_data
# @category SNMP
##
function usm_AES_priv_protocol( priv_key, msg_data, alg )
{
  var aes_key;
  var alglen = 16;
  if ('AES192' >< alg) alglen = 24;
  if ('AES256' >< alg) alglen = 32;
  aes_key = substr( priv_key, 0, (alglen-1) );

  if ( ! defined_func( 'aes_cfb_encrypt' ) )
  {
    dbg::detailed_log(lvl:1, src:SCRIPT_NAME + ':' + FUNCTION_NAME, name:'snmp_func', msg:'AES encryption not supported');
    return NULL;
  }

  var salt, iv, ret, ciphertext, i, j, outblock, msg_block;

  salt = PEPP64 + mkdword( PEPPER );

  iv = mkdword( auth_engine_boots ) + mkdword( auth_engine_time ) + salt;

  if ( PEPPER < 0xffffffff )
    PEPPER += 1;
  else
    PEPPER = rand();

  # Pad out to mod 16 for AES encryption.
  while ( ( strlen( msg_data  ) % 16 ) != 0 )
    msg_data  += '\x00';

  i = 0;
  ciphertext = '';
  j = strlen( msg_data );
  while( i < j )
  {
    msg_block = substr( msg_data, i, i + 15 );
    outblock = aes_cfb_encrypt( data:msg_block, key:aes_key, iv:iv );
    iv = outblock[1];
    ciphertext += outblock[0];
    i += 16;
  }
  ret[0] = salt;
  ret[1] = ber_put_octet_string (string:ciphertext );
  return ret;
}


##
# Performs RFC3414's AES Privacy decryption for SNMPv3
#
# @param <priv_key> Privacy key to use
# @param <msg_data> Message to privacy decrypt
# @param <priv_param> Salt to use
# @param <alg> AES algorithm being used, to calculate size to operate on
# @renark Consult section 3.3.2 of http://www.ietf.org/rfc/rfc3826.txt for details
# @return NULL if there is no salt, else
#         privacy decrypted msg_data
# @category SNMP
##
function usm_AES_priv_decrypt( priv_key, msg_data, priv_param, alg )
{
  if ( ! defined_func( 'aes_cfb_decrypt' ) )
  {
    dbg::detailed_log(lvl:1, src:SCRIPT_NAME + ':' + FUNCTION_NAME, name:'snmp_func', msg:'AES encryption not supported');
    return NULL;
  }

  var aes_key;
  var alglen = 16;
  if ('AES192' >< alg) alglen = 24;
  if ('AES256' >< alg) alglen = 32;
  aes_key = substr( priv_key, 0, (alglen-1) );

  var salt, iv, ret, plaintext, i, j, outblock, msg_block;
  salt = priv_param;

  if ( isnull( salt ) || ( strlen( salt  ) != 8 ) )
  return NULL;

  iv = mkdword( auth_engine_boots ) + mkdword( auth_engine_time ) + salt;

  # Pad out to mod 16 for AES encryption.
  while ( ( strlen( msg_data  ) % 16 ) != 0 )
    msg_data  += '\x00';

  i = 0;
  plaintext = '';
  j = strlen( msg_data );
  while( i < j )
  {
    msg_block = substr( msg_data, i, i + 15 );
    outblock = aes_cfb_decrypt( data:msg_block, key:aes_key, iv:iv );
    iv = outblock[1];
    plaintext += outblock[0];
    i += 16;
  }
  return plaintext;
}


##
# Performs RFC3414's DES Privacy encryption for SNMPv3
#
# @param <priv_key> Privacy key to use
# @param <msg_data> Message to privacy encrypt
# @renark Consult section 8 of http://www.ietf.org/rfc/rfc3414.txt for details
# @return privacy encrypted msg_data
# @category SNMP
##
function usm_DES_priv_protocol( priv_key, msg_data )
{
  var des_key, pre_iv, salt, iv, ret, ciphertext, i, key, inter, block;

  des_key = substr( priv_key, 0, 7 );
  pre_iv  = substr( priv_key, 8, 15 );

  salt = mkdword( auth_engine_boots ) + mkdword( PEPPER );
  if ( PEPPER < 0xffffffff )
    PEPPER += 1;
  else
    PEPPER = rand();

  iv = XOR( bitstring1:salt, bitstring2:pre_iv );

  # Pad out to mod 8 = 0 for DES encryption.
  while ( ( strlen( msg_data  ) % 8 ) != 0 )
    msg_data  += '\x00';

  i = 0;
  ciphertext = '';
  key = iv;
  while( i < strlen( msg_data ) )
  {
    block = substr( msg_data, i, i + 7 );
    block = XOR( bitstring1:key, bitstring2:block );
    inter = DES( in:block, key:set_des_key(key:des_key), _string:FALSE, type:1 );         # TYPE 1 = encrypt
    ciphertext += inter;
    key = inter;
    i += 8;
  }
  ret[0] = salt;
  ret[1] = ber_put_octet_string (string:ciphertext );
  return ret;
}


##
# Performs RFC3414's DES Privacy decryption for SNMPv3
#
# @param <priv_key> Privacy key to use
# @param <msg_data> Message to privacy decrypt
# @param <priv_param> Salt to use
# @renark Consult section 8.2.4.2 of http://www.ietf.org/rfc/rfc3414.txt for details
# @return privacy decrypted msg_data
# @category SNMP
##
function usm_DES_priv_decrypt( priv_key, msg_data, priv_param )
{
  var des_key, pre_iv, iv, ret, plaintext, i, key, plainblock, inter, block;

  des_key = substr( priv_key, 0, 7 );
  pre_iv  = substr( priv_key, 8, 15 );

  iv = XOR( bitstring1:priv_param, bitstring2:pre_iv );

  if ( ( strlen( msg_data  ) % 8 ) != 0 )
    return NULL;

  i = 0;
  plaintext = '';
  key = iv;
  while( i < strlen( msg_data ) )
  {
    block = substr( msg_data, i, i + 7 );
    inter = DES( in:block, key:set_des_key(key:des_key), _string:FALSE, type:0 );           # TYPE 0 = decrypt
    plainblock = XOR( bitstring1:key, bitstring2:inter );
    plaintext += plainblock ;
    key = block;
    i += 8;
  }
  return plaintext;
}


##
# Performs RFC3414's encryption for SNMPv3
#
# @param <priv_passwd> Privacy key to use
# @param <msg_data> Message to privacy encrypt
# @param <auth_alg> Authentication algorithm to use
# @param <priv_alg> Privacy algorithm to use
# @renark Consult section 3.1.8 of http://www.ietf.org/rfc/rfc3414.txt for details
# @return privacy and authentication encrypted msg_data
# @category SNMP
##
function snmpv3_encrypt_outgoing( priv_passwd, msg_data, auth_alg, priv_alg )
{
  var priv_key;
  var min_length = 16;
  priv_alg = toupper( priv_alg);
  var cisco_key_extension = 'C' >< priv_alg;
  if ('AES192' >< priv_alg) min_length = 24;
  if ('AES256' >< priv_alg) min_length = 32;
  priv_key = get_kb_item( 'Secret/SNMP/v3/LocalizedPrivKey' );
  if ( ! priv_key )
  {
    priv_key = password_to_key( passwd:priv_passwd, alg:auth_alg, min_length:min_length, cisco_extension:cisco_key_extension );
    replace_kb_item( name:'Secret/SNMP/v3/LocalizedPrivKey', value:base64( str:priv_key ) );
  }
  else
    priv_key = base64_decode( str:priv_key );
  if ( priv_alg == 'DES' )
    return usm_DES_priv_protocol( priv_key:priv_key, msg_data:msg_data );
  else if ( 'AES' >< priv_alg )
    # AES-192 and AES-256 use the same function
    return usm_AES_priv_protocol( priv_key:priv_key, msg_data:msg_data, alg:priv_alg );
}


##
# Performs RFC3414's encryption for SNMPv3
#
# @param <msg_data> Message to privacy decrypt
# @param <priv_alg> Privacy algorithm to use
# @param <priv_alg> Salt to use
# @renark Consult section 3.2.8 of http://www.ietf.org/rfc/rfc3414.txt for details
# @return privacy decrypted msg_data
# @category SNMP
##
function snmpv3_decrypt_incoming( msg_data, priv_alg, priv_param  )
{
  var priv_key;
  priv_alg = toupper( priv_alg);

  priv_key = get_kb_item( 'Secret/SNMP/v3/LocalizedPrivKey' );
  if ( ! priv_key )
    return NULL;   # If we haven't stored the priv_key  then this is not a response to a message we sent.
  else
    priv_key  = base64_decode( str:priv_key  );

  if  ( priv_alg == 'DES' )
    return usm_DES_priv_decrypt( priv_key:priv_key, msg_data:msg_data, priv_param:priv_param);
  else if ( 'AES' >< priv_alg)
    return usm_AES_priv_decrypt( priv_key:priv_key, msg_data:msg_data, priv_param:priv_param, alg:priv_alg );
  return NULL;
}


##
# Perform generic SNMPv3 request
#
# @param <socket> Connection to make request and receive reply
# @param <community> community string
# @param <oid> oid to send
# @param <timeout> seconds to wait for response
# @param <op> operation to conduct
# @param <ret_err> Response to give in case of error
# @param <non_repeaters> optional non repeaters flag to use for OP_GET_BULK_REQUEST operations
# @param <max_repetitions> optional max repetitions flag to use for OP_GET_BULK_REQUEST operations
# @return NULL if SNMP connection failed or creds could not be parsed, else
#         snmp response from target
# @category SNMP
##
function snmpv3_request( socket, community, oid, timeout, op, ret_err, non_repeaters, max_repetitions )
{
  var seq, req, res, msg_flags, msg_global_data, snmp_header, whole_msg, snmpv3_connected;
  var salt, authentication_data, auth_alg;

  if ( isnull(op) ) op = OP_GET_REQUEST;
  # Message Global Data Values
  if ( ! msg_id )
    msg_id = rand();
  msg_flags = raw_string( MSG_REPORTABLE_FLAG );                    # Set the reportable flag.

  # If we are missing any authoritative engine data then we must be making an initial connection attempt
  if( ( ! auth_engine_id ) || ( ! auth_engine_boots  ) || ( !  auth_engine_time  ) )
  {
    msg_global_data = snmpv3_put_msg_global_data( msg_max_size:MSG_MAX_SIZE,
                                                  msg_flags:msg_flags,
                                                  msg_security_model:USM_SECURITY_MODEL );
    snmpv3_connected = snmpv3_initial_request( socket:socket, msg_global_data:msg_global_data, timeout:timeout);
    if(get_kb_item("SNMP/v3/FAILED"))
      return NULL;
  }

  # creds is global so that it can be used in the return auth and decoding.
  creds = split( base64_decode( str:substr( community, 1 ) ), sep:';', keep:FALSE );
  # Confirm that creds has split out properly
  if ( ( ! creds ) || ( max_index( creds ) != 6 ) )
    return NULL;

  auth_alg = AUTH_ALGORITHMS[creds[2]];
  snmpv3_auth = get_kb_item('Secret/SNMP/v3/auth_password');
  snmpv3_priv = get_kb_item('Secret/SNMP/v3/priv_password');
  if (creds[5] != USM_LEVEL_NO_AUTH_NO_PRIV && isnull(auth_alg))
  {
    dbg::detailed_log(lvl:1, src:SCRIPT_NAME + ':' + FUNCTION_NAME, name:'snmp_func',
        msg:'Unsupported authentication algorithm: ' + creds[2]);
    return NULL;
  }

  # Bit bash the security level with the reportable flag.
  msg_flags = ord( msg_flags ) | creds[ 5 ];
  msg_global_data = snmpv3_put_msg_global_data( msg_max_size:MSG_MAX_SIZE,
                                                msg_flags:msg_flags,
                                                msg_security_model:USM_SECURITY_MODEL  );

  # Assemble the OID sequence
  seq = ber_put_sequence( seq:make_list( ber_put_oid( oid:oid ), ber_put_null() ) );

  # Assemble msg data
  req = snmp_assemble_request_data( seq:seq, op:op, non_repeaters:non_repeaters, max_repetitions:max_repetitions);
  salt = NULL;

  if ( creds[ 5 ] == USM_LEVEL_AUTH_PRIV )
  {
    req = snmpv3_encrypt_outgoing( priv_passwd:snmpv3_priv, msg_data:req, auth_alg:auth_alg, priv_alg:creds[ 4 ] );
    salt = req[ 0 ];
    req = req[ 1 ];
  }

  authentication_data = snmp_assemble_authentication_data(  auth_engine_data:snmp_put_engine_data(),
                                                            msg_user_name:creds[ 0 ],
                                                            msg_auth_param:auth_empty_string(alg:auth_alg),
                                                            msg_priv_param:salt );

  # Assmble the snmp message header
  snmp_header =  ber_put_int( i:SNMP_VERSION ) + msg_global_data + authentication_data;

  # Assemble the whole message
  whole_msg = ber_put_sequence( seq:make_list( snmp_header, req ) );

  # Sign the message for authentication if required
  if (creds[5] != USM_LEVEL_NO_AUTH_NO_PRIV)
    whole_msg = snmpv3_authenticate_outgoing( auth_passwd:snmpv3_auth, whole_msg:whole_msg, alg:auth_alg );

  # Send and get the result
  res = snmp_exchange( socket:socket, data:whole_msg, timeout:timeout, ret_err:ret_err);

  return res;
}


##
# Perform a get bulk SNMPv3 request
#
# @param <socket> Connection to make request and receive reply
# @param <community> community string
# @param <oid> oid to send
# @param <timeout> seconds to wait for response
# @param <non_repeaters> optional non repeaters flag to use for OP_GET_BULK_REQUEST operations
# @param <max_repetitions> optional max repetitions flag to use for OP_GET_BULK_REQUEST operations
# @return snmp response from target of two parallel arrays of OIDs and values
# @category SNMP
##
function snmp_get_bulk_request( socket, community, oid, timeout, non_repeaters, max_repetitions )
{
  var seq, req, res;

  if ( isnull(non_repeaters) )
    non_repeaters = 0;

  if ( isnull(max_repetitions) )
    max_repetitions = 10;

  if  ( isnull( timeout ) )
    timeout = 2;

  if ( ( community[ 0 ] == ';' ) && ( SNMP_VERSION == 0x03 ) )
  {
    res = snmpv3_request(
      socket:socket,
      community:community,
      oid:oid,
      timeout:timeout,
      op:OP_GET_BULK_REQUEST,
      non_repeaters:non_repeaters,
      max_repetitions:max_repetitions
    );
    return res;
  }
  else
  {
    seq = make_list(ber_put_oid (oid:oid), ber_put_null());

    seq = make_list( ber_put_sequence(seq:seq) );

    req =  ber_put_int (i:snmp_request_id)          + # Request Id
           ber_put_int (i:non_repeaters)            + # non-repeaters
           ber_put_int (i:max_repetitions)          + # max_repeaters
           ber_put_sequence (seq:seq);                # Object Identifier
    req =  ber_put_int (i:SNMP_VERSION)             + # version
           ber_put_octet_string (string:community)  + # community string
           ber_put_get_bulk_pdu (pdu:req);            # PDU type

    req =  ber_put_sequence (seq:make_list(req));

    snmp_request_id += 1;

    send (socket:socket, data:req);
    res = snmp_reply (socket:socket, timeout:timeout);

    return res;
  }
}


##
# Perform a generic SNMP request
#
# @param <socket> Connection to make request and receive reply
# @param <community> community string
# @param <oid> oid to send
# @param <timeout> seconds to wait for response
# @return NULL if unsuccessful response, else
#         snmp response from target
# @category SNMP
##
function snmp_request( socket, community, oid, timeout )
{
  var seq, req, res;

  if  ( isnull( timeout ) )
    timeout = 2;

  if ( ( community[ 0 ] == ';' ) && ( SNMP_VERSION == 0x03 ) )
  {
    res = snmpv3_request( socket:socket, community:community, oid:oid, timeout:timeout, op:OP_GET_REQUEST );
    if ( isnull(res) ) return NULL;
    else return res[1];
  }
  else
  {
    seq = make_list(ber_put_oid (oid:oid), ber_put_null());

    seq = make_list( ber_put_sequence(seq:seq) );

    req =  ber_put_int (i:snmp_request_id)          + # Request Id
           ber_put_int (i:0)                        + # Error Status: NO ERROR (0)
           ber_put_int (i:0)                        + # Error Index (0)
           ber_put_sequence (seq:seq);                # Object Identifier

    req =  ber_put_int (i:SNMP_VERSION)             + # version
           ber_put_octet_string (string:community)  + # community string
           ber_put_get_pdu (pdu:req);                 # PDU type

    req =  ber_put_sequence (seq:make_list(req));

    snmp_request_id += 1;

    send (socket:socket, data:req);
    res = snmp_reply (socket:socket, timeout:timeout);

    if ( isnull( res ) )
      return NULL;
    else
      return res[1];
  }
}


##
# Perform an SNMP request_next
#
# @param <socket> Connection to make request and receive reply
# @param <community> community string
# @param <oid> oid to send
# @param <timeout> seconds to wait for response
# @param <ret_err> error to return if there is an error
# @return NULL if unsuccessful response, else
#         snmp response from target
# @category SNMP
##
function snmp_request_next (socket, community, oid, timeout, ret_err)
{
  var seq, req, res;

  if ( ( community[ 0 ] == ';' ) && ( SNMP_VERSION == 0x03 ) )
  {
    return snmpv3_request( socket:socket, community:community, oid:oid, timeout:timeout, op:OP_GET_NEXT_REQUEST, ret_err:ret_err );
  }
  else
  {
    seq = make_list(ber_put_oid (oid:oid), ber_put_null());

    seq = make_list( ber_put_sequence(seq:seq) );

    req = ber_put_int (i:snmp_request_id)          + # Request Id
          ber_put_int (i:0)                        + # Error Status: NO ERROR (0)
          ber_put_int (i:0)                        + # Error Index (0)
          ber_put_sequence (seq:seq);                # Object Identifier

    req = ber_put_int (i:SNMP_VERSION)             + # version
          ber_put_octet_string (string:community)  + # community string
          ber_put_get_next_pdu (pdu:req);            # PDU type

    req = ber_put_sequence (seq:make_list(req));
  }

  snmp_request_id += 1;

  send (socket:socket, data:req);

  res = snmp_reply (socket:socket, timeout:timeout, ret_err:ret_err);

  if (end_mib)
    return NULL;

  return res;
}


##
# Perform an SNMP request_set
#
# @param <socket> Connection to make request and receive reply
# @param <community> community string
# @param <oid> oid to send
# @param <type> entry type to set
# @param <value> entry value to set
# @param <timeout> seconds to wait for response
# @param <ret_err> error to return if there is an error
# @return NULL if SNMPv3 or connection terminated or value falsy or unsupported type, else
#         snmp response from target after sending request set
# @category SNMP
##
function snmp_request_set (socket, community, oid, type, value, timeout, ret_err)
{
  var seq, req, res, val;

  if ( ( community[ 0 ] == ';' ) && ( SNMP_VERSION == 0x03 ) )
  {
    #return snmpv3_request( socket:socket, community:community, oid:oid, timeout:timeout, op:OP_SET_REQUEST, ret_err:ret_err );
    # not implemented yet
    return NULL;
  }
  else
  {
    seq = make_list(ber_put_oid (oid:oid));

    if (type == TYPE_INTEGER)
      val = ber_put_int(i:value);
    else if (type == TYPE_OCTET_STRING)
      val = ber_put_octet_string(string:value);
    else if (type == TYPE_NULL)
      val = ber_put_null();
    else
    {
      #err_print('snmp_request_set(): unsupported type "' + type + '"');
      return NULL;
    }

    if(!isnull(val))
      append_element(var:seq, value:val);
    else
      return NULL;

    seq = make_list( ber_put_sequence(seq:seq) );

    req = ber_put_int (i:snmp_request_id)          + # Request Id
          ber_put_int (i:0)                        + # Error Status: NO ERROR (0)
          ber_put_int (i:0)                        + # Error Index (0)
          ber_put_sequence (seq:seq);                # Object Identifier

    req = ber_put_int (i:SNMP_VERSION)             + # version
          ber_put_octet_string (string:community)  + # community string
          ber_put_set_pdu (pdu:req);                 # PDU type

    req = ber_put_sequence (seq:make_list(req));
  }

  snmp_request_id += 1;

  send (socket:socket, data:req);

  res = snmp_reply (socket:socket, timeout:timeout, ret_err:ret_err);

  if (end_mib)
    return NULL;

  return res;
}


##
# Scans for SNMP strings using get_next_pdu
#
# @param <socket> Connection to make request and receive reply
# @param <community> community string
# @param <oid> oid to send
# @return string list of discovered SNMP strings
# @category SNMP
##
function scan_snmp_string(socket, community, oid)
{
  var soid, list, port;

  list = NULL;
  soid = oid;

  while(1)
  {
    port = snmp_request_next (socket:socket, community:community, oid:soid);
    if (!isnull(port) && egrep (pattern:"^" + str_replace(string:oid, find:".", replace:'\\.') + "\.", string:port[0]))
    {
      if ( strlen(port[1] ) ) list = list + port[1] + '\n';
      soid = port[0];
    }
    else
      break;
  }

  return list;
}


##
# Checks if product OID is from the same manufacturer
#
# @param <manufacturer> Passed manufacturer string
# @param <oid> oid to check
# @return TRUE if oid found at start of manufacturer string, else
#         FALSE
# @category SNMP
##
function is_valid_snmp_product(manufacturer, oid)
{
  var match;
  if (egrep(pattern:"^" + manufacturer + '\\..*', string:oid))
    return TRUE;

  # egrep's assessment not always correct (CS-37406)
  if (stridx(oid, manufacturer + '.') == 0)
    return TRUE;

  return FALSE;
}


##
# Checks if oid is mostly the same
#
# @param <origoid> Original oid to check
# @param <oid> second oid to check
# @return TRUE if oid found at start of origoid string, else
#         FALSE
# @category SNMP
##
function issameoid(origoid, oid)
{
  var tmp;

  if (strlen(oid) < strlen(origoid))
    return FALSE;

  tmp = substr(oid,0,strlen(origoid));

  if ( tmp != origoid + ".")
    return FALSE;

  return TRUE;
}


##
# Sets SNMP_VERSION value
#
# @param <version> Version to set
# @return TRUE if global SNMP_VERSION is different, else
#         NULL
# @category SNMP
##
function set_snmp_version( version )
{
  if  ( SNMP_VERSION != version )
  {
    _SNMP_VERSION = SNMP_VERSION;
    SNMP_VERSION = version;
    return TRUE;
  }
  return NULL;
}


##
# Resets SNMP_VERSION value to _SNMP_VERSION
#
# @return TRUE if global SNMP_VERSION !- _SNMP_VERSION, else
#         NULL
# @category SNMP
##
function reset_snmp_version()
{
  if  ( SNMP_VERSION != _SNMP_VERSION )
  {
    SNMP_VERSION = _SNMP_VERSION;
    return TRUE;
  }
  return NULL;
}


##
# Set kb to indicate an SNMPv3 failure
#
# @return NULL
# @category SNMP
##
function snmp_set_kb_auth_problem()
{
  var kb_prefix = "Host/Auth/SNMP/";
  var port, port_list;

  port = 161;
  port_list = get_kb_list("SNMP/port");
  if(max_index(port_list) > 0)
    port = port_list[0];

  replace_kb_item(name:kb_prefix + port + "/Problem", value:TRUE);
}


##
# Set kb to detail why an SNMPv3 failure occurred
#
# @param <port> SNMPv3 port with error
# @param <login> SNMPv3 username
# @param <error> SNMPv3 error
# @param <snmp_ver> SNMPv3 version
# @return NULL, sets KBs
# @category SNMP
##
function snmp_set_kb_auth_failure(port, login, error, snmp_ver)
{
  var kb_prefix = "Host/Auth/SNMP/";
  var port_list;

  if (empty_or_null(port))
  {
    port_list = get_kb_list("SNMP/port");
    if(max_index(port_list) > 0)
      port = port_list[0];
  }
  if (empty_or_null(error))
    error = "No details available";
  if (empty_or_null(login))
  {
    if (empty_or_null(snmp_ver)) snmp_ver = 1;
    if (snmp_ver >= 3) login = "Unknown user";
    else login = "Unknown community string";
  }

  replace_kb_item(name:kb_prefix + port + "/Failure", value:TRUE);
  lcx::log_issue(type:lcx::ISSUES_AUTH, msg:error, port:port,
    proto:lcx::PROTO_SNMP, user:login);
}

##
# Set kb to detail that an SNMPv3 connection succeeded
#
# @param <port> SNMPv3 port with error
# @param <login> SNMPv3 username
# @param <snmp_ver> SNMPv3 version
# @return NULL, sets KBs
# @category SNMP
##
function snmp_set_kb_auth_success(port, login, snmp_ver)
{
  if (empty_or_null(port)) return;
  var kb_prefix = "Host/Auth/SNMP/";

  if (empty_or_null(login))
  {
    if (empty_or_null(snmp_ver)) snmp_ver = 1;
    if (snmp_ver >= 3) login = "Unknown user";
    else login = "Unknown community string";
  }
  replace_kb_item(name:kb_prefix+port+"/Success", value:login);
}


##
# Check and return the SNMP port
#
# @param [port:int]          SNMP UDP port to connect to (optional) (default: SNMP/port, 161)
# @param [exit_on_fail:bool] Exit on fail (optional) (default: true)
#
# @return UDP port if successful; NULL otherwise
##
function snmp_port(port, exit_on_fail)
{
  # Defaults
  if (!port)
    port = get_kb_item('SNMP/port');

  if (!port)
    port = 161;

  if (isnull(exit_on_fail))
    exit_on_fail = true;
  
  # Check port state
  if (!get_udp_port_state(port))
  {
    if (exit_on_fail)
      audit(AUDIT_PORT_CLOSED, port);

    return NULL;
  }
  
  return port;
}


##
# Connect to the SNMP port
#
# @param [port:int]          SNMP UDP port to connect to (optional)
# @param [exit_on_fail:bool] Exit on fail (optional) (default: true)
#
# @return socket handle if successful; NULL otherwise
##
function snmp_connect(port, exit_on_fail)
{
  # Defaults
  if (isnull(exit_on_fail))
    exit_on_fail = true;

  # Argument validation
  if (empty_or_null(port))
  {
    if (exit_on_fail)
      exit(1, 'Missing required argument: "port"');

    return NULL;
  }
  
  # Connect to socket
  var soc = open_sock_udp(port);
  if (!soc)
  {
    if (exit_on_fail)
      audit(AUDIT_SOCK_FAIL, port, 'UDP');

    return NULL;
  }
  
  return soc;
}