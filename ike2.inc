#TRUSTED 84bfb7301eb9ed3c58f01ee4c64fa8118a03352715d31ece94922a624788780542965abb9e36c0114ced7770f56b44ae37aa4f1478d56794c3c3af663b5a816fefe2dd06eb21ca31f96c83112001dc36fd6e897b9f0873926bd78d1b4ff50a41f1208e6c327e0391cde2a6a482f942e5ab920cfae9b0c463279bd3a0853f99d8bcf0dd78c1d8c3d385773dd6941f8402273304e03639a0e85ed52f665b8b842846d30b0b0a850a33893cd2bb0f44689578c7270cfb8c004d22a9919c53f685500da2f55dafc4bcfa7aa9d5113f37f05b7e8531712b83d41e028ec751311cf5111a76795783b14d253603653f367f3ad2c6829b446fecf040a5255c62ad2437764be37aa452def446c4e1667716cc151aa46285bea2ee329dca330b7b87d39b02b3e823c6e211d7917b4b45351acffb4ca62d65121861f0c5b2e5f07ce36bee25cb86db105e93f97d184a8beb5431cedf1c0664b056876e59dc145ec1e5fc0531fc025a37e1f8a188042b4a7c679345baaeb8b88bff6566de9c7ae25ef4ac2dc951b2806dd08414bf7e6a6184b12583756267eab06ec0587da4022520b2bb38cbdfef9dd92355f1e4e95d614c4d481c2a5ac092c09df0e4fcb81f04c072c740a661ffb9e9ee3a6588aadfb9f0c0d62d2ff6a07b26c36c58b2cf7676f8d1d92bb63715f646b83caf6cfd6d36542ff6e35fc6a0399fa9e3adcde54ac1b68283c564
#TRUST-RSA-SHA256 0174296c89fa40c35fde24e529f22e9a94b60f2088b0f7c8d4de5594063ce8415a6c2a93be3a4a02bab490fbf49d7e0e1782c5776598f497d876a830619fe95265731cb4f205aabcc69b87850ff70192f750a5ed2e4d2913f20ad8c4e8813d8d1332f6358a6231be3672122ba6ffb8bd6dfa390abe980808f51d5e2e1b24ce5acdcd068f109d0719a8f6c553b233fdfa079fcfd255ad99c94a728c70cba4a32d2d55bfad01211de62dbe43edb1b65bba027d3a4f4c49422c0e194b951b6fe0b30a99ac8fbcfff9cb9dc128f4ff99592c6b768b4ad265afbcf0abbcc1d7c1bc2ff9eff74f60919f9db49cc47eb1b1f635de2d81cec863dfe8b135340e68a86696740cfed95ad14b5193051595955d9ec421eaac4d41a768f5e026e7c17724eb57b054e2fbcad9ca79835d0399811f715ec7cf49707c15f25dc776f35115142ce759d7f9bf963a46a6f36284c8c69c8949ccc92dfd6da84fae525cea3c4cca4f88565fb3c12171966c48ecbeb87dfdc4a1d477f6c5189333aa6071652e05d3d2f7e1f6320a2f72ac3f64e8d89a3b4b780e336751cd50afdb6484c35158315c9851ddff60f4f9e65318e265f06ffce84fc8827d282e05bf730f6ecf1dcfacabb2e4b7fe7fb2be9e79f610c14b0e0433848b183715e97d81d41f47b3f009ea70174721c8be206a7369ab4e977afd89301782e632b3b7a9ffadb585dc52dadad7d7ce
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
#
include("compat_shared.inc");
include("byte_func.inc");
include("ike_common.inc");

#pragma const
#
# Exchange Types
#
var IKE2_EXCH_SA_INIT            = 34;
var IKE2_EXCH_AUTH               = 35;
var IKE2_EXCH_CREATE_CHILD_SA    = 36;
var IKE2_EXCH_INFORMATIONAL      = 37;


#
# Flags in the IKE header
#
var IKE2_FLAG_INITIATOR     = 0x08;
var IKE2_FLAG_VERSION       = 0x10;
var IKE2_FLAG_RESP          = 0x20;



#
# Payload types
#
var IKE2_PAYLOAD_NONE       = 0;
var IKE2_PAYLOAD_SA         = 33;
var IKE2_PAYLOAD_KE         = 34;
var IKE2_PAYLOAD_IDI        = 35;
var IKE2_PAYLOAD_IDR        = 36;
var IKE2_PAYLOAD_CERT       = 37;
var IKE2_PAYLOAD_CERTREQ    = 38;
var IKE2_PAYLOAD_AUTH       = 39;
var IKE2_PAYLOAD_NONCE      = 40;
var IKE2_PAYLOAD_NOTIFY     = 41;
var IKE2_PAYLOAD_DELETE     = 42;
var IKE2_PAYLOAD_VID        = 43;
var IKE2_PAYLOAD_TSI        = 44;
var IKE2_PAYLOAD_TSR        = 45;
var IKE2_PAYLOAD_ENCRYPTED  = 46;
var IKE2_PAYLOAD_CONFIG     = 47;
var IKE2_PAYLOAD_EAP        = 48;




#
# Protocol IDs in Proposal payload
#
var IKE2_PROTO_IKE        = 1;
var IKE2_PROTO_AH         = 2;
var IKE2_PROTO_ESP        = 3;


#
# Transform types in Transform payload
#
var IKE2_XFORM_ENC          = 1;
var IKE2_XFORM_PRF          = 2;
var IKE2_XFORM_INTEG        = 3;
var IKE2_XFORM_DH_GROUP     = 4;
var IKE2_XFORM_ESN          = 5; # Extended Sequence Numbers

#
# Transform IDs for IKE2_XFORM_ENC
#
var IKE2_ENC_DES_IV64     = 1;
var IKE2_ENC_DES          = 2;
var IKE2_ENC_3DES         = 3;
var IKE2_ENC_RC5          = 4;
var IKE2_ENC_IDEA         = 5;
var IKE2_ENC_CAST         = 6;
var IKE2_ENC_BLOWFISH     = 7;
var IKE2_ENC_3IDEA        = 8;
var IKE2_ENC_DES_IV32     = 9;
var IKE2_ENC_NULL         = 11;
var IKE2_ENC_AES_CBC      = 12;
var IKE2_ENC_AES_CTR      = 13;

#
# Attributes type used in the Transform substructure
#
var IKE2_ATTR_KEYLEN      = 14;


#
# Transform IDs for IKE2_XFORM_PRF
#
var IKE2_PRF_HMAC_MD5     = 1;
var IKE2_PRF_HMAC_SHA1    = 2;
var IKE2_PRF_HMAC_TIGER   = 3;
var IKE2_PRF_AES128_XCBC  = 4;

#
# Transform IDs for IKE2_XFORM_INTEG
#
var IKE2_INTEG_HMAC_MD5_96   = 1;
var IKE2_INTEG_HMAC_SHA1_96  = 2;
var IKE2_INTEG_DES_MAC       = 3;
var IKE2_INTEG_KPDK_MD5      = 4;
var IKE2_INTEG_AES_XCBC_96   = 5;


#
# Notification types
#
# Error types
var IKN2_UNSUPPORTED_CRITICAL_PAYLOAD   = 1;
var IKN2_INVALID_IKE_SPI                = 2;
var IKN2_INVALID_MAJOR_VERSION          = 3;
var IKN2_INVALID_SYNTAX                 = 7;
var IKN2_INVALID_MESSAGE_ID             = 9;
var IKN2_INVALID_SPI                    = 11;
var IKN2_NO_PROPOSAL_CHOSEN             = 14;
var IKN2_INVALID_KE_PAYLOAD             = 17;
var IKN2_AUTHENTICATION_FAILED          = 24;
var IKN2_SINGLE_PAIR_REQUIRED           = 34;
var IKN2_NO_ADDITIONAL_SAS              = 35;
var IKN2_INTERNAL_ADDRESS_FAILURE       = 36;
var IKN2_FAILED_CP_REQUIRED             = 37;
var IKN2_TS_UNACCEPTABLE                = 38;
var IKN2_INVALID_SELECTORS              = 39;
var IKN2_TEMPORARY_FAILURE              = 43;
var IKN2_CHILD_SA_NOT_FOUND             = 44;
# Status types
var IKN2_INITIAL_CONTACT                = 16384;
var IKN2_SET_WINDOW_SIZE                = 16385;
var IKN2_ADDITIONAL_TS_POSSIBLE         = 16386;
var IKN2_IPCOMP_SUPPORTED               = 16387;
var IKN2_NAT_DETECTION_SOURCE_IP        = 16388;
var IKN2_NAT_DETECTION_DESTINATION_IP   = 16389;
var IKN2_COOKIE                         = 16390;
var IKN2_USE_TRANSPORT_MODE             = 16391;
var IKN2_HTTP_CERT_LOOKUP_SUPPORTED     = 16392;
var IKN2_REKEY_SA                       = 16393;
var IKN2_ESP_TFC_PADDING_NOT_SUPPORTED  = 16394;
var IKN2_NON_FIRST_FRAGMENTS_ALSO       = 16395;


#
# Authentication methods
#
var IKE2_AUTH_RSA_SIG       = 1;
var IKE2_AUTH_SHARED_KEY    = 2;
var IKE2_AUTH_DSS_SIG       = 3;

#pragma const(false)

##
# Creates an IKEv2 header
#
# @param ispi [data]    Initiator SPI (known as Initiator Cookie in IKEv1)
# @param rspi [data]    Responder SPI (known as Responder Cookie in IKEv1)
# @param payload [int]  Type of the first payload following the header
# @param mj_ver [int]   IKE major version
# @param mn_ver [int]   IKE minor version
# @param exch [int]     Exchange type
# @param flags [int]    Header flags
# @param msgid [int]    Message ID
# @param len [int]      Total length of the IKE PDU
#
# @return [data] formatted IKEv2 header
# @remark see RFC 5996, section 3.1
#
##
function ike2_hdr(ispi, rspi, payload, exch, flags, msgid, len)
{
  return ike_hdr(ispi:ispi, rspi:rspi, payload:payload, exch:exch, mj_ver:2, mn_ver: 0, flags:flags, msgid:msgid, len:len);
}

##
# Creates an IKEv2 payload header
#
# @param next [int] Type of next payload
# @param c [int]    Critical payload bit; default = 0
# @param len [int]  Total length of the payload, including the payload header
# @return [data]    Formatted payload header
# @remark
#   - For more information, see RFC 5996, section 3.2
#
##
function ike2_payload_hdr(next,c,len)
{
  local_var hdr;

  if(isnull(c)) c = 0;

  hdr = mkbyte(next) +
        raw_string(((c & 0x1) << 7) & 0xff) +
        mkword(len); # payload length includes len of payload hdr
  return hdr;
}

##
# Creates an IKEv2 payload
#
# @param next [int]   Type of next payload
# @param c [int]      Critical payload bit; default = 0
# @param data [data]  Raw data of the payload
# @return [data]      Formatted payload
#
##
function ike2_payload(next, c, data)
{
  local_var hdr, len;

  if(isnull(c)) c = 0;

  len = strlen(data) + 4; # 4-byte payload header

  hdr = ike2_payload_hdr(next:next, c:c, len:len);
  return (hdr + data);
}

##
# Creates an IKEv2 Security Association (SA) payload
#
# @param next [int]       Type of next payload
# @param c [int]          Critical payload bit; default = 0
# @param proposals [data] One or more proposal substructures
# @return [data]          Formatted SA payload
# @remark
#   For more details, see RFC 5996, section 3.3
##
function ike2_payload_sa(next,c, proposals)
{
  return ike2_payload(next:next,c:c, data:proposals);
}


##
# Creates an IKEv2 Authentication (AUTH) payload
#
# @param next [int]       Type of next payload
# @param c [int]          Critical payload bit; default = 0
# @param method [int]     Authentication method
# @param data [data]      Authentication data
# @return [data]          Formatted AUTH payload
# @remark
#   For more details, see RFC 5996, section 3.8
##
function ike2_payload_auth(next, c, method, data)
{
  data = mkbyte(method) + mkword(0) + data;
  return ike2_payload(next:next,c:c, data:data);
}


##
# Creates an IKEv2 Proposal Substructure
#
# @param next [int]       0 (last) or 2 (next proposal)
# @param num [int]        Proposal number
# @param proto [int]      Protocol ID
# @param spi [data]       SPI
# @param xforms [list]    A list of formatted transform substructure(s)
# @return [data]          A formatted proposal substructure
# @remark
#   For more details, see RFC 5996, section 3.3.1
##
function ike2_proposal(next, num, proto, spi, xforms)
{
  local_var data, t, xf;

  xf = NULL; foreach t (xforms) xf += t;

  data =  mkbyte(num) +
          mkbyte(proto) +
          mkbyte(strlen(spi)) +
          mkbyte(max_index(xforms)) +
          spi+
          xf;
  return ike2_payload(next:next, data:data);

}

##
# Creates an IKEv2 Transform Substructure
#
# @param next [int]       0 (last) or 3 (next proposal)
# @param type [int]       Transform type
# @param id [int]         Transform ID
# @param attrs [data]     Transform attributes
# @return [data]          A formatted transform substructure
# @remark
#   For more details, see RFC 5996, section 3.3.2
##
function ike2_xform(next, type, id, attrs)
{
  local_var data;

  data =  mkbyte(type) +
          mkbyte(0) +
          mkword(id) +
          attrs;
  return ike2_payload(next:next,data:data);
}

##
# Creates an IKEv2 Key Exchange (KE) payload
#
# @param next [int]       Type of next payload
# @param c [int]          Critical payload bit; default = 0
# @param group[int]       DH group number
# @param data [data]      Key exchange data
# @return [data]          Formatted KE payload
# @remark
#   For more details, see RFC 5996, section 3.4
##
function ike2_payload_ke(next,c, group, data)
{
  data = mkword(group) + mkword(0) + data;
  return ike2_payload(next:next,c:c, data:data);
}

##
# Creates an IKEv2 Notify payload
#
# @param next [int]       Type of next payload
# @param c [int]          Critical payload bit; default = 0
# @param msg_type[int]    Notify Message Type
# @param data [data]      Notification data
# @return [data]          Formatted Notify payload
# @remark
#   For more details, see RFC 5996, section 3.10
##
function ike2_payload_notify(next,c, msg_type, data)
{
  data = 
    mkbyte(0) +        # Protocol ID
    mkbyte(0) +        # SPI Size, currently not supported by the ike2_payload* funcs
    mkword(msg_type) + # Message Type
    data;              # Notification Data
  return ike2_payload(next:next,c:c, data:data);
}

##
# Parses raw_data of an IKEv2 Notification payload
#
# @anonparam [data]   Raw data of the Notification payload
# @return [array]     ret['proto'] [int]  - Protocol ID; 1 = IKE, 2 = ESP, 3 = AH
#                     ret['spi'] [data]   - SPI
#                     ret['type'] [int]   - Notification type
#                     ret['data'] [data]  - Notification data
#
# @remark
#   - This function returns NULL if it fails.
#   - For more details, see RFC 5996, section 3.10
##
function ike2_parse_notify()
{
  local_var data, len, pos, ret, spi_size;

  data = _FCT_ANON_ARGS[0];
  len = strlen(data);

  # Sizes for proto, spi_size, and notification type fields
  if(len < 1 + 1 + 2) return NULL;

  pos = 0;
  ret['proto']    = getbyte(blob:data, pos:pos); pos += 1;
  spi_size        = getbyte(blob:data, pos:pos); pos += 1;
  ret['type']     = getword(blob:data, pos:pos); pos += 2;

  # Get SPI
  if(spi_size)
  {
    # Invalid spi_size
    if(pos + spi_size > len) return NULL;

    ret['spi'] = substr(data, pos, pos + spi_size -1 );

    pos += spi_size;
  }

  if(pos < len)
  {
    # Get Notification data
    ret['data'] = substr(data, pos);
  }
  else if(pos > len)
  {
    return NULL;
  }
  return ret;

}


##
# Creates an IKEv2 Proposal for PROTO_IKE
#
# @param enc_list [list]    A list of encryption algorithms (including key length) to be included in the proposal
# @param integ_list [list]  A list of integrity algorithms to be included in the proposal
# @param group_list [list]  A list of DH groups to be included in the proposal
# @param prf_list [list]    A list of Pseudo Random Functions to be included in the proposal
# @param next [int]         Indicates whether another proposal follows this one; 0 = NONE, 2 = MORE, default = NONE
# @param num [int]          Proposal number; default = 1
# @return [data]            Formatted proposal with various transforms
#
# @remark
#   - if enc_list contains all combine-mode ciphers, integ_list is not needed.
#   - RFC 5996, section 2.7 says:
#       Each IPsec protocol proposal contains one or more transforms.  Each
#       transform contains a Transform Type.  The accepted cryptographic
#       suite MUST contain exactly one transform of each type included in the
#       proposal.
#
##
function ike2_proposal_ike(enc_list, integ_list, group_list, prf_list, next, num)
{
  local_var attrs, enc, group, i, id, integ, keylen, prop, prf, xforms;


  xforms = NULL;
  i = 0;

  # Encryption algorithms
  foreach enc (enc_list)
  {
    id = enc[0];
    keylen = enc[1];

    if(keylen) attrs = ike_attr(type: IKE2_ATTR_KEYLEN, value: keylen);
    else       attrs = NULL;

    xforms[i++] = ike2_xform(next:3, type: IKE2_XFORM_ENC, id:id, attrs: attrs);
  }

  # Integrity algorithms
  foreach integ (integ_list)
  {
    xforms[i++] = ike2_xform(next:3, type: IKE2_XFORM_INTEG, id:integ, attrs: NULL);
  }

  # DH groups
  foreach group (group_list)
  {
    xforms[i++] = ike2_xform(next:3, type: IKE2_XFORM_DH_GROUP, id:group, attrs: NULL);
  }

  # PRF
  foreach prf (prf_list)
  {
    if(prf == prf_list[max_index(prf_list) -1])
      xforms[i++] = ike2_xform(next:0, type: IKE2_XFORM_PRF, id:prf, attrs: NULL);
    else
      xforms[i++] = ike2_xform(next:3, type: IKE2_XFORM_PRF, id:prf, attrs: NULL);
  }

  if(isnull(xforms)) return NULL;

  if(isnull(next)) next = 0; # no more proposal to follow this proposal
  if(isnull(num))  num  = 1; # first proposal

  return ike2_proposal(next: next, num:num, proto:IKE2_PROTO_IKE, spi:'', xforms: xforms);

}

##
# Performs an IKEv2 SA_INIT exchange
#
# @param enc_list [list]    A list of encryption algorithms (including key length) to be included in the proposal
# @param integ_list [list]  A list of integrity algorithms to be included in the proposal
# @param group_list [list]  A list of DH groups to be included in the proposal
# @param prf_list [list]    A list of Pseudo Random Functions to be included in the proposal
# @param ke_group [int]     DH group number to be used in the KE payload
# @param ispi [data]        Initiator SPI
# @return [array]           A IKE status object;
#                           STATUS_SUCCESS - Remote IKEv2 daemon returns a SA payload, status['info'] contains the parsed PDU.
#                           STATUS_FAILURE - IKEv2 daemon is not listening on remote host
#                           STATUS_FAILURE_UNEXPECTED - Parsing errors etc; status['info'] has more details.
#                           IKN2_XXX       - Notification type/code sent by remote IKEv2 daemon; status['info'] contains the notification data.
#
#
##
function ike2_sa_init(enc_list, integ_list, group_list, prf_list, ke_group, ispi)
{
  local_var dh_x, hdr, ke, nonce, notify, payloads, pdu, prop, res, ret, sa;


  #
  # Check params
  #
  # ke_group MUST be one in group_list
  if(! item_in_list(list: group_list, item: ke_group))
    return ike_status(STATUS_FAILURE_UNEXPECTED, 'Invalid DH group specification.');


  prop = ike2_proposal_ike(enc_list: enc_list, integ_list: integ_list, group_list:group_list,
                         prf_list:prf_list);

  if(isnull(prop)) return ike_status(STATUS_FAILURE_UNEXPECTED, 'Failed to create an IKE proposal.');

  #
  # SA payload
  #
  sa = ike2_payload_sa(next:IKE2_PAYLOAD_KE, proposals:prop);
  if(isnull(sa)) return ike_status(STATUS_FAILURE_UNEXPECTED, 'Failed to create an SA payload.');

  #
  # Key Exchange Payload
  #
  # Compute g^x mod p.
  dh_x = bn_mod_exp(IKE_DH_GENERATOR_2, rand_str(length:16), IKE_DH_GROUP[ke_group]);
  ke = ike2_payload_ke(next:IKE2_PAYLOAD_NONCE, group:ke_group, data:dh_x);
  if(isnull(ke)) return ike_status(STATUS_FAILURE_UNEXPECTED, 'Failed to create a KE payload.');

  #
  # Nonce Payload
  #
  nonce = ike2_payload(next: 0, data:rand_str(length:32));

  payloads = sa + ke + nonce;

  hdr = ike2_hdr( ispi: ispi,
                  rspi: crap(data:'\x00', length:8),
                  payload: IKE2_PAYLOAD_SA,
                  exch: IKE2_EXCH_SA_INIT,
                  flags: IKE2_FLAG_INITIATOR,
                  msgid: 0,
                  len:IKE_HDR_SIZE + strlen(payloads));

  pdu = hdr + payloads;
  res = ike2_pcap_sendrecv(data:pdu);
  if(isnull(res)) return ike_status(STATUS_FAILURE,'No response from UDP port '+IKE_PORT+' to an IKE_SA_INIT message.');

  # Parse the response
  ret = ike2_parse(res);
  if(isnull(ret)) return ike_status(STATUS_FAILURE_UNEXPECTED, 'Received an invalid IKEv2 packet from remote UDP port '+IKE_PORT+'.');

  # Double check
  hdr       = ret['hdr'];
  payloads  = ret['payloads'];

  if(isnull(hdr))       return ike_status(STATUS_FAILURE_UNEXPECTED, 'Failed to get IKEv2 header in the response.');
  if(isnull(payloads))  return ike_status(STATUS_FAILURE_UNEXPECTED, 'Failed to get any IKEv2 payload in the response.');

  #
  # Check to see if the response is an SA_INIT response or a notification
  #

  # Got a notification
  if(hdr['np'] == IKE2_PAYLOAD_NOTIFY)
  {
    # First payload is the NOTIFY payload
    notify = payloads[0];
    notify = ike2_parse_notify(notify['raw_data']);

    if(isnull(notify) || isnull(notify['type']))
      return ike_status(STATUS_FAILURE_UNEXPECTED, 'Failed to parse IKEv2 Notification payload in the response.');
    #
    # return IKN2_XXX as status code, along with notification data
    #
    return ike_status(notify['type'], notify['data']);
  }
  # SUCCESS, ret is the SA_INIT response
  else if (hdr['np'] == IKE2_PAYLOAD_SA)
    return ike_status(STATUS_SUCCESS, ret);
  else
    return ike_status(STATUS_FAILURE_UNEXPECTED, 'Unexpected first payload type ('+hdr['np']+') found in the response.');

}

#
# Wrappers
#
function ike2_parse()
{
  local_var pdu;

  pdu = _FCT_ANON_ARGS[0];
  return ike_parse(pdu);
}
function ike2_pcap_sendrecv(data, filter, timeout)
{
  return ike_pcap_sendrecv(data:data, filter:filter, timeout:timeout);
}

function ike2_sendrecv(socket, data)
{
  return ike_sendrecv(socket: socket, data: data);
}

function ike2_attr(type, value)
{
  return ike_attr(type:type, value:value);
}

function ike2_cipher()
{
  local_var id, keylen;

  id      = _FCT_ANON_ARGS[0];
  keylen  = _FCT_ANON_ARGS[1];

  return ike_cipher(id, keylen);

}
