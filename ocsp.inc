#TRUSTED 06bdb35471990b7baaa95a87c9ffa193d177f3f8ae6987b62b020f7c01b6bed1ebcbb4394d5646f063b9b870b92b118fabf7c9af726a15eac59198a38ea160b6c5592b52bab40f9b79a01a7d2009ca9793fdc3001b052166e0428b26c182dde59e75a8251cddd909482f9892d74e0a919199b614865254a56acc347cf8bb268a0bc89125b03f0528593726d4b22f447f6c308c77685501fe0c03ade470b79191933e8466a046bffcecf3b516c3586b0f2a4970766324440d5497eaa73b22c3ccd264fd928e558a8577c11d6fc614f98351eb8ce5a1e827c7bf2086137fcc1c2130ca0ad443b87a83422262e09175f5f73b6b8e455346e86b8f4fc2ec45859990509c10f61753acb5bd7a60f1d1ef0b886929c9462a83e6822cb347acb88d4338a2cf1a52641cf74b2bd4953e71945fefbeed375d3e340d14a39797b4a4ce7b17d1e6b2b771bf560a1a3255426e437775480f9b938e9e73666d4c2f6325346fc36c289bfb6b15ac295e8929c981452d4d51d94e7c9ce151a551df045c3aef7e4418fdcf134d32ea932de9815c93f8779e0245fc8b9c275818b4d008ca63d3e9d3ecbf679024f129d0e22d2f51331b2a434ce82af3793f55e7ce5648e1c0241a72fa199c0750d28a7d84195b466a8a84aafb3f969629733ba3e482e44b0021b2cc8d18483e8f94ff0422fe76723e65e730df3ef93e12889f675acb8395d87c7464
#TRUST-RSA-SHA256 0a93973c3590bbb3104d70b9cb0a8047b7af160a69806c7f2a449e2cb863a3d81692c1c621fbb64fc6836e5405e4a3c83a0a83a160005298dd1f024c32875b929fe35c6f1da9b2e2d24d82b925a232f76dc711916a01802da362ea8c0ae0e1ca90e66c62a052e707a852361e419164017421583afce5853005842b15efb86ec2f795c8c2209823ec46ccf5fd425a1c5f5e55132de871af25fcb641bbece038f9d9bba11beaf6b085823277f69f571849f2ed7f5dfcee6de274a53b6436cd26d969a682ac4f6338625e9e77629a95179e1e27217de232b1ed8ac3509cc6a30774ceb4750df3f782902d78b7608e6419f6ef8effc98f10e0b7306a04448a6931ce829776ebd18ffb1320240f8d821c8ed916c85db8dbf4d615e7e60fee9841a65fb4f16d64dc9f1840c3467757d8fa20d1203abcf21a17f5f618028a116bb21f6df6aae121524fa6ab44dd6328b3481a54d9f0a1cfb204be23b737f69ddccc1dbdd63b110621797279bef9cbc10093aaf9f0a92b3b87fdf24679fe2cce289e6ab479c0a8a3cce26b9215ecbf493aaff3860bb2f95f7404ac0d33ec4f8f4cc60a225d72fb57bfa32e9cf5913cc029bd52c16297dfd6ce1d61c06cb64c97dff8b2c659c364078309ddb02c747ba240f5ff7eb72527544907d7ebfb396404e92f81dcd8d3493b6c70d22ea0ef5bd1df2195027b7db4e078f0713b66ed07b803e2baf6

#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# Revision: 1.10
#
# @include x509.inc
# @include http.inc
# @include ssl_func.inc
# @include kerberos_func.inc
#

#
# This is an implementation of RFCs 2560 & 6960 "X509 Internet Public Key Infrastructure
# Online Certificate Status Protocol".
# NB: RFC 6960 obsoletes 2560. Check to see if this makes a difference in our impl.
#
# @citation: https://www.ietf.org/rfc/rfc2560.txt
#

include("compat_shared.inc");
include("asn1_tags.inc");
include("x509_func.inc");
include("http.inc");
include("ssl_funcs.inc");
include("der_funcs.inc");
include("dump.inc");
include("spad_log_func.inc");
include("debug.inc");
include("charset_func.inc");


global_var OCSP_VERBOSE_DEBUG = 0;
global_var OCSP_DEBUG_PREFIX='';

##
# A convenience wrapper around detailed_log()
# 
# @param [fname:string] the calling function's name
# @param [note:string] the debugging message
# @param [value:any] a value to serialize and display with the message (optional)
# @param [plain:boolean] set to TRUE to override serialization and display value plainly
# @param [override:integer] use to override the global OCSP_VERBOSE_DEBUG variable
# @param [lvl:integer] debug level integer to be passed to detailed_log() (optional, defaults to 3)
#
# @return [string] The note string, with prepended OCSP_DEBUG_PREFIX if non-empty
##
function dbglog(fname, note, value, plain, override, lvl) 
{
  var details, vtype;
  var debug = OCSP_VERBOSE_DEBUG;

  if (empty_or_null(lvl))
    lvl = 3;
  if (empty_or_null(fname))
    fname = FUNCTION_NAME;

  if (!isnull(override))
    debug = override;

  if (!(debug || get_kb_item('global_settings/enable_plugin_debugging'))) 
    return FALSE;
  
  if (!empty_or_null(value))
    details = {"Value": {"lvl": lvl, "value": value}};

  if (!plain && !empty_or_null(value))
  {
    vtype = typeof_ex(value);
    if ((vtype == 'data' || vtype == 'string') && value != get_ascii_printable(string:value))
      details = {"Data": {"lvl": lvl, "value": value}};
    else
      details = {"Value": {"lvl": lvl, "value": obj_rep(value)}};
  }

  if (OCSP_DEBUG_PREFIX) note = OCSP_DEBUG_PREFIX + ': ' + note;
  dbg::detailed_log(
    src: fname,
    lvl: lvl,
    msg: note,
    msg_details: details);
  return note;
}


##
# Returns the public key from a certificate in the format expected by
# the OCSP protocol (as actually implemented, not necessarily as specified
# in the RFCs). 
# 
# @param [parsed_cert:array] an x509 certificate, in array format, as parsed by
#                    parse_der_cert() in x509_func.inc
# @return a data type value containing the bytes needed in the construction
# of an OCSP request, or NULL on failure.
##
function _get_public_key_bytes(parsed_cert)
{
  var fname = '_get_public_key_bytes';
  if (typeof_ex(parsed_cert) != 'array' ||
      isnull(parsed_cert['tbsCertificate']) ||
      isnull(parsed_cert['tbsCertificate']['rawSubjectPublicKeyInfo']))
  {
    dbglog(fname:fname, lvl:1, note:'parsed_cert has wrong structure', value:parsed_cert);
    return NULL;
  }

  var ret = parsed_cert['tbsCertificate']['rawSubjectPublicKeyInfo'];
  if (ret[0] == '\x00') ret = substr(ret, 1, strlen(ret)-1);
  if (isnull(ret)) return NULL;
  dbglog(fname:fname, lvl:3, note:'Returning', value:ret);
  return ret;
}

##
# Extracts the issuer in DER format from the certificate
#
# @param [parsed_cert:array] the a certificate in array format (as returned
#               by parse_der_cert())
# @return a byte string or NULL on failure
##
function _get_issuer_der_bytes(parsed_cert)
{
  var fname = '_get_issuer_der_bytes';
  if (typeof_ex(parsed_cert) != 'array' ||
      isnull(parsed_cert['tbsCertificate']) ||
      isnull(parsed_cert['tbsCertificate']['rawIssuer']))
  {
    dbglog(fname:fname, lvl:1, note:'parsed_cert has wrong structure', value:parsed_cert);
    return NULL;
  }

  var ret = parsed_cert['tbsCertificate']['rawIssuer'];
  dbglog(fname:fname, lvl:3, note:'Returning', value:ret, override:0);
  return ret;
}

##
# Extracts from the server's certificate, the OCSP URI to make the OCSP request to
#
# @param [cert:array] a certificate that has been through "parse_der_cert"
#
# @return a URI string or NULL
##
function get_ocsp_address(cert)
{
  var ext = NULL;
  dbglog(fname:'get_ocsp_address', lvl:3, note:'Cert parameter', value:cert);
  var tbs_cert = cert["tbsCertificate"];
  var extension = cert_get_ext(id:EXTN_AUTHORITY_INFORMATION_ACCESS, cert:tbs_cert);
  foreach(ext in extension)
  {
	  if (ext["accessMethod"] == "1.3.6.1.5.5.7.48.1")
	  {
		  return ext["accessLocation"]["uniformResourceIdentifier"];
	  }
  }
  dbglog(fname:'get_ocsp_address', lvl:1, note:'ext["accessLocation"]["uniformResourceIdentifier"] not found in parsed cert');
  return NULL;
}


###
# Extracts from the server's certificate, the CA Issuer's URI. This URI should
# point at a certificate. We will use the certificate to generate the OCSP
# request (see: RFCs 2560 & 6960 4.1.1). And possibly to validate the OCSP response.
#
# @param [cert:array] a certificate that has been through "parse_der_cert"
# @return a URI string or NULL
###
function get_issuer_cert_address(cert)
{
  var ext = NULL;
  var tbs_cert = cert["tbsCertificate"];
  var extension = cert_get_ext(id:EXTN_AUTHORITY_INFORMATION_ACCESS, cert:tbs_cert);
  foreach(ext in extension)
  {
	  if (ext["accessMethod"] == "1.3.6.1.5.5.7.48.2")
	  {
		  return ext["accessLocation"]["uniformResourceIdentifier"];
	  }
  }
  dbglog(fname:'get_issuer_cert_address', lvl:1, note:'ext["accessLocation"]["uniformResourceIdentifier"] not foundin parsed cert');
  return NULL;
}

###
# This function generates the payload of an OCSP request as described
# in RFCs 2560 & 6960 section 4.1. We use SHA-1 as our hashing algorithm.
#
# @param [server_der_cert:data] the server's certificate in DER format
# @param [issuer_der_cert:data] the issuer's certificate in DER format
# @return an array of bytes representing an ocsp-request - or null.
###
function create_ocsp_request(server_der_cert, issuer_der_cert)
{
  var fname = 'create_ocsp_request';
  var key_bytes;
  # we need to pass the include_blobs:TRUE parameter in order to get the key blob
  # relying on parse_der_cert() to do the parsing, rather than reinventing the
  # wheel over and over again, makes this code much more maintainable.
  var issuer_parsed_cert = parse_der_cert(cert:issuer_der_cert, include_blobs:TRUE);
  var server_parsed_cert = parse_der_cert(cert:server_der_cert, include_blobs:TRUE);
  dbglog(fname:fname, lvl:3, note:'Parsed server cert', value:server_parsed_cert, override:0);
  var serial = server_parsed_cert["tbsCertificate"]["serialNumber"];
  dbglog(fname:fname, lvl:3, note:'Serial number', value:serial);
  key_bytes = _get_public_key_bytes(parsed_cert:issuer_parsed_cert);
  if (isnull(key_bytes))
  {
    dbglog(fname:fname, lvl:1, note:'failed to extract public key bytes from cert');
    return NULL;
  }
  dbglog(fname:fname, lvl:3, note:'Retrieved key_bytes', value:key_bytes);

  # extract the issuer bytes
  var issuer_bytes = _get_issuer_der_bytes(parsed_cert:server_parsed_cert);
  dbglog(fname:fname, lvl:3, note:'Retrieved issuer_bytes', value:issuer_bytes, override:0);
  if (isnull(issuer_bytes))
  {
	  return NULL;
  }

  #################################################################
  # OCSPRequest SEQUENCE {
  #   tbsRequest SEQUENCE {
  #   --- should have a version integer here ---
  #     requestList SEQUENCE {
  #       Request SEQUENCE {
  #         CertId SEQUENCE {
  #           hashAlgorithm SEQUENCE {
  #             OID(1.3.14.3.2.26 (SHA-1)),
  #           }
  #           issuerNameHash OCTET_STRING(SHA1 of key_bytes),
  #           issuerKeyHash  OCTET_STRING(SHA1 of issuer_bytes),
  #           CertificateSerialNumber INTEGER(server_cert[tbsCertificate][serialNumber]),
  #         }
  #       }
  #     }
  #   }
  # }
  #################################################################
  # oid 1.3.14.3.2.26 (SHA-1)
  var hash_algorithm = der_encode(tag:ASN1_SEQUENCE,
                                  data:der_encode(tag:ASN1_OBJECT, 
                                                  data:'\x2b\x0e\x03\x02\x1a') 
                                  );

  var issuer_name_hash = der_encode(tag:ASN1_OCTET_STRING, data:SHA1(issuer_bytes));
  var issuer_key_hash = der_encode(tag:ASN1_OCTET_STRING, data:SHA1(key_bytes));
  var serial_number = der_encode(tag:ASN1_INTEGER, data:serial);

  var certId_seq = der_encode(tag:ASN1_SEQUENCE, 
                              data: hash_algorithm
                                  + issuer_name_hash
                                  + issuer_key_hash
                                  + serial_number);

  var request      = der_encode(tag:ASN1_SEQUENCE, data:certId_seq);
  var tbs_request  = der_encode(tag:ASN1_SEQUENCE, data:request);
  var request_cert = der_encode(tag:ASN1_SEQUENCE, data:tbs_request);
  var request_list = der_encode(tag:ASN1_SEQUENCE, data:request_cert);

  dbglog(fname:'create_ocsp_request', lvl:3, note:'Returning:', value:request_list);
  return request_list;
}

###
# Reads the "responseStatus" in the OCSPResponse. This byte indicates
# if the request was processed successfully. See RFCs 2560 & 6960 4.2.1 for possible values.
# 
# @param [ocsp_response:data] an OCSPResponse in DER format
#
# @return FALSE if the response fails to parse, and the status byte otherwise.
##
function response_status(ocsp_response)
{
  var seq = der_decode(data:ocsp_response);
  var fname = 'response_status';
  if (isnull(seq) || seq[0] != ASN1_SEQUENCE)
  {
    dbglog(fname:fname, lvl:1, note:'Failed to parse OCSP response', value:ocsp_response);
    return FALSE;
  }
  seq = seq[1];

  var resp_status = der_decode(data:seq);
  if (isnull(resp_status) || resp_status[0] != 0x0a || len(resp_status[1]) != 1)
  {
    dbglog(fname:fname, lvl:1, note:'Failed to parse inner 0x30 of OCSP response', 
        value:seq);
    return FALSE;
  }
  dbglog(fname:fname, lvl:3, note:'Succeeded in parsing status from OCSP response. Returning...',
      value:resp_status[1]);

  return resp_status[1];
}

##
# Reads the "responseStatus" in the OCSPResponse. This byte indicates
# if the request was processed successfully. See RFCs 2560 & 6960 4.2.1 for possible values.
#
# @param [ocsp_response:data] an OCSPResponse in DER format
#
# @return [boolean] TRUE if the status was '0' (good) and FALSE otherwise
##
function response_status_good(ocsp_response)
{
  var status = response_status(ocsp_response:ocsp_response);
  if (status == FALSE) return FALSE;
  else if (status == '\x00' && typeof(status) == 'data') return TRUE;
  else return FALSE;
}

##
# Reads the "responseStatus" in the OCSPResponse. This byte indicates
# if the request was processed successfully. This function returns
# a string with the status as listed in RFCs 2560 & 6960 4.2.1.
#
# @param [ocsp_response:data] an OCSPResponse in DER format
#
# @return [string] a string representation of the response status
##
function printable_status(ocsp_response)
{
  var resp_status = response_status(ocsp_response:ocsp_response);
  switch (resp_status)
  {
    case FALSE:  return "OCSPResponse is Malformed";
    case '\x00': return "Good";
    case '\x01': return "Malformed Request";
    case '\x02': return "Internal Error";
    case '\x03': return "Try Again Later";
    case '\x05': return "Signature Required";
    case '\x06': return "Unauthorized";
    default:     return "Unknown Status";
  }
}

##
# Parses the OCSPResponse down to the CertStatus in SingleResponse. See RFCs 2560 & 6960 4.2.1.
#
# @param [ocsp_response:data] an OCSPResponse in DER format
# @param [serial_number:data] the serial number of the certificate we are verifying
#
# @return NULL on failure. Otherwise a string describing the result (ie 'Not Revoked', 'Revoked', 'Unknown')
##
function get_revocation_status(ocsp_response, serial_number)
{
  var fname = 'get_revocation_status';
  if (isnull(serial_number)) 
  {
    dbglog(fname:fname, lvl:1, note:'No serial number provided');
    return NULL;
  }
  var seq = der_decode(data:ocsp_response);
  if (isnull(seq) || seq[0] != ASN1_SEQUENCE) 
  { 
    dbglog(fname:fname, lvl:1, note:'der_decode failed to parse expected 0x30 type', value:seq);
    return NULL;
  }
  seq = seq[1];

  # ResponseStatus - enumerated
  var resp_status = der_decode(data:seq);
  if (isnull(resp_status) || resp_status[0] != 0x0a || len(resp_status[1]) != 1) return NULL;

  if (resp_status[1] != '\x00') return NULL;

  # responseBytes[0]
  var responseBytes = der_decode(data:seq, pos:resp_status[2]);
  if (isnull(responseBytes) || responseBytes[0] != 0xa0) return NULL;

  # ResponseBytes sequence
  var responseBytesSeq = der_decode(data:responseBytes[1]);
  if (isnull(responseBytesSeq) || responseBytesSeq[0] != ASN1_SEQUENCE) return NULL;

  # verify that this is a basic ocsp response
  var responseType = der_decode(data:responseBytesSeq[1]);
  if (isnull(responseType) || responseType[0] != 6) return NULL;
  var responseOid = der_decode_oid(oid: responseType[1]);
  if (responseOid != "1.3.6.1.5.5.7.48.1.1") return NULL;

  # response - octet string
  var response = der_decode(data:responseBytesSeq[1], pos:responseType[2]);
  if (isnull(response) || response[0] != 4) return NULL;

  # first sequence in BasicOCSPResponse
  var response_seq = der_decode(data:response[1]);
  if (isnull(response_seq) || response_seq[0] != ASN1_SEQUENCE) return NULL;

  # ResponseData sequence
  var responseDataSeq = der_decode(data:response_seq[1]);
  if (isnull(responseDataSeq) || responseDataSeq[0] != ASN1_SEQUENCE) return NULL;

  # ResponseData version 
  var version = der_decode(data:responseDataSeq[1]);
  if (!isnull(version) && version[0] == 0xa0)
  {
	  # this is not in accordance with the RFC. Yandex Cert Authority, you are on notice!
	  version = der_decode(data:responseDataSeq[1], pos:version[2]);
  }
  if (isnull(version) || (version[0] != 0xa2 && version[0] != 0xa1)) return NULL;

  # Get the responder id
  var responder_string = der_decode(data:version[1]);
  if (isnull(responder_string) || (responder_string[0] != 0x04 && responder_string[0] != ASN1_SEQUENCE)) return NULL;

  # Get the produced at time
  var produced_at = der_decode(data:responseDataSeq[1], pos:version[2]);
  if (isnull(produced_at) || produced_at[0] != 0x18) return NULL;

  # responses sequence
  var responses = der_decode(data:responseDataSeq[1], pos:produced_at[2]);
  if (isnull(responses) || responses[0] != ASN1_SEQUENCE) return NULL;

  # loop over the single response sequences until we hit the correct serial number
  var response_serial = NULL;
  var singleResponse = NULL;
  var position = 0;

  do
  {
	  singleResponse = der_decode(data:responses[1], pos:position);
	  if (isnull(singleResponse) || singleResponse[0] != ASN1_SEQUENCE) return NULL;

	  # update position in case we need to loop again
	  if (singleResponse[2] <= position) return NULL;
	  position = singleResponse[2];

	  # cert sequence
	  var certSequence = der_decode(data:singleResponse[1]);
	  if (isnull(certSequence) || certSequence[0] != ASN1_SEQUENCE) return NULL;

	  # hash algorithm
	  var hashAlgorithm = der_decode(data:certSequence[1]);
	  if (isnull(hashAlgorithm) || hashAlgorithm[0] != ASN1_SEQUENCE) return NULL;

	  # issuer name hash
	  var issuerNameHash = der_decode(data:certSequence[1], pos:hashAlgorithm[2]);
	  if (isnull(issuerNameHash)) return NULL;

	  # issuer key hash
	  var issuerKeyHash = der_decode(data:certSequence[1], pos:issuerNameHash[2]);
	  if (isnull(issuerKeyHash)) return NULL;

	  # serial number
	  response_serial = der_decode(data:certSequence[1], pos:issuerKeyHash[2]);
	  if (isnull(response_serial)) return NULL;
  }
  while(hexstr(serial_number) != hexstr(response_serial[1]));

  # certStatus
  var certStatus = der_decode(data:singleResponse[1], pos:certSequence[2]);
  if (isnull(certStatus)) return NULL;

  if (certStatus[0] == 0x80 || certStatus[0] == 0xa0) return "Not Revoked";
  else if (certStatus[0] == 0xa1) return "Revoked";
  return "Unknown";
}

##
# The OCSPResponse is followed by an RSA signature. This function decrypts
# the signature with the provided certificate's public key and computes the
# hash over OCSPResponse to validate the decrypted hash.
#
# @ramark This currently fails if the responder attaches ANOTHER cert after the
# signature. WHY IS THIS ALLOWED?! ARHGLJ
#
# The above is a TODO
# @param [ocsp_response:data] an OCSPResponse in DER format
# @param [issuer_der_cert:data] the issuer's certificate in DER format
#
# @return NULL on failure or a string describing the verification state. Current options:
# 	- "Unhandled Signature Algorithm"
# 	- "Valid Signature"
# 	- "Invalid Signature"
#	  - "Decryption Failed"
##
function verify_ocsp_response(ocsp_response, issuer_der_cert)
{

  var fname = 'verify_ocsp_response';
  var seq = der_decode(data:ocsp_response);
  if (isnull(seq) || seq[0] != ASN1_SEQUENCE || isnull(seq[1])) return NULL;
  seq = seq[1];

  # ResponseStatus - enumerated
  var resp_status = der_decode(data:seq);
  if (isnull(resp_status) || resp_status[0] != 0x0a || strlen(resp_status[1]) != 1) return NULL;
  if (resp_status[1] != '\x00') return NULL;

  # responseBytes[0]
  var responseBytes = der_decode(data:seq, pos:resp_status[2]);
  if (isnull(responseBytes) || responseBytes[0] != 0xa0) return NULL;

  # ResponseBytes sequence
  var responseBytesSeq = der_decode(data:responseBytes[1]);
  if (isnull(responseBytesSeq) || responseBytesSeq[0] != ASN1_SEQUENCE) return NULL;

  # verify that this is a basic ocsp response
  var responseType = der_decode(data:responseBytesSeq[1]);
  if (isnull(responseType) || responseType[0] != 6) return NULL;
  var responseOid = der_decode_oid(oid: responseType[1]);
  if (responseOid != "1.3.6.1.5.5.7.48.1.1") return NULL;

  # response - octet string
  var response = der_decode(data:responseBytesSeq[1], pos:responseType[2]);
  if (isnull(response) || response[0] != 4) return NULL;

  # first sequence in BasicOCSPResponse
  var response_seq = der_decode(data:response[1]);
  if (isnull(response_seq) || response_seq[0] != ASN1_SEQUENCE) return NULL;

  # ResponseData sequence
  var responseDataSeq = der_decode(data:response_seq[1]);
  if (isnull(responseDataSeq) || responseDataSeq[0] != ASN1_SEQUENCE) return NULL;

  var signature_algo_seq = der_decode(data:response_seq[1], pos:responseDataSeq[2]);
  if (isnull(signature_algo_seq) || signature_algo_seq[0] != ASN1_SEQUENCE) return NULL;

  # The algorithm used to sign the OCSPResponse hash
  var signature_algo = der_decode(data:signature_algo_seq[1]);
  if (isnull(signature_algo) || signature_algo[0] != 6) return NULL;
  var algorithm = der_decode_oid(oid:signature_algo[1]);
  if ("1.2.840." >!< algorithm) return ("Unhandled Signature Algorithm: " + algorithm);

  # These bytes are the signed hash of the OCSPResponse
  var signature_bits = der_decode(data:response_seq[1], pos:signature_algo_seq[2]);
  if (ord(signature_bits[1][0]) == 0)
  {
	  signature_bits[1] = substr(signature_bits[1], 1, len(signature_bits[1]) - 1);
  }
  # The responder can chose to sign with a cert included at the end.
  var signer_cert = der_decode(data:response_seq[1], pos:signature_bits[2]);
  if (!isnull(signer_cert) && signer_cert[0] == 0xa0)
  {
	  signer_cert = der_decode(data:signer_cert[1]);
	  if (!isnull(signer_cert) && signer_cert[0] == ASN1_SEQUENCE) issuer_der_cert = signer_cert[1];
  }

  var parsed_issuer_cert = parse_der_cert(cert:issuer_der_cert);
  dbglog(fname:fname, lvl:3, note:'Retrieved parsed_issuer_cert', value:parsed_issuer_cert);
  if (isnull(parsed_issuer_cert)) return NULL;

  var n = parsed_issuer_cert["tbsCertificate"]["subjectPublicKeyInfo"][1][0];
  var e = parsed_issuer_cert["tbsCertificate"]["subjectPublicKeyInfo"][1][1];
  if (isnull(n) || isnull(e)) return NULL;
  if (ord(n[0]) == 0) n = substr(n, 1, strlen(n) - 1);
  dbglog(fname:fname, lvl:3, note:'Retrieved n', value:n);
  dbglog(fname:fname, lvl:3, note:'Retrieved e', value:e);

  var decrypted = rsa_public_decrypt(sig:signature_bits[1], n:n, e:e);
  if (isnull(decrypted)) 
  {
    dbglog(fname:fname, lvl:1, note:'Decryption of signature failed with n = '+n+' and e = '+e,
        value:signature_bits[1]);
    return "Decryption Failed";
  } 

  var hashed = NULL;
  var hash_this = substr(response_seq[1], 0, responseDataSeq[2] - 1);
  if (algorithm == "1.2.840.113549.1.1.11") hashed = SHA256(hash_this);
  else if(algorithm == "1.2.840.113549.1.1.5") hashed = SHA1(hash_this);
  else return ("Unhandled Signature Algorithm: " + algorithm);

  if (hashed >< decrypted) return "Valid Signature";
  return "Invalid Signature";
}

##
# Determines if the certificate supports OCSP or not.
#
# use one of two optional parameters:
# @param [server_der_cert:data] the server's certificate in DER format
# @param [server_parsed_cert:array] the DER cert as parsed by parse_der_cert
#
# @return [boolean] TRUE if the certificate supports OCSP and FALSE otherwise
##
function has_ocsp(server_der_cert, server_parsed_cert)
{
  if (isnull(server_parsed_cert))
  {
    server_parsed_cert = parse_der_cert(cert:server_der_cert);
  }
  if (isnull(server_parsed_cert)) return FALSE;

  var ocsp_location = get_ocsp_address(cert:server_parsed_cert);
  var crt_location = get_issuer_cert_address(cert:server_parsed_cert);
  dbglog(fname:'has_ocsp', lvl:3, note:'Retrieved ocsp_location', value:ocsp_location);
  dbglog(fname:'has_ocsp', lvl:3, note:'Retrieved crt_location', value:crt_location);
  return !isnull(ocsp_location) && !isnull(crt_location);
}

##
# Given a certificate, this function will determine if it has been revoked or not.
# Before calling this function, verify the cert supports OSCP via "has_ocsp".
#
# @param [server_der_cert:data] the server's certificate in DER format
#
# @return NULL on failure or an two index array with the results. For example:
#	  1. ['verify_ocsp_response': Valid Signature]['revocation_status': Not Revoked]
#   2. ['ocsp_failure': OCSP responder failed to respond.]
#   3. ['ocsp_failure': OCSP responder replied with a bad status: OCSPResponse is malformed]
#   4. ['ocsp_failure': Failed to download issuer cert.]
##
function do_ocsp(server_der_cert)
{
  var fname = 'do_ocsp';
  var server_parsed_cert;
  # Use of 'target' without keepalive appears to be broken.
  http_disable_keep_alive();

  if (isnull(server_parsed_cert))
  {
    server_parsed_cert = parse_der_cert(cert:server_der_cert); 
  }
  dbglog(fname:fname, lvl:2, note:'parse_der_cert returned', value:server_parsed_cert);
  if (isnull(server_parsed_cert)) return NULL;

  var ocsp_location = get_ocsp_address(cert:server_parsed_cert);
  dbglog(fname:fname, lvl:2, note:'get_ocsp_address returned', value:ocsp_location);
  if (isnull(ocsp_location)) return NULL;

  var crt_location = get_issuer_cert_address(cert:server_parsed_cert);
  dbglog(fname:fname, lvl:2, note:'get_issuer_cert_address returned', value:crt_location);
  if (isnull(crt_location)) return NULL;

  var ocsp_fields = split_url(url:ocsp_location);
  if (isnull(ocsp_fields)) return NULL;

  var crt_fields = split_url(url:crt_location);
  if (isnull(crt_fields)) return NULL;

  # retrieve the the issuer certificate
  if (crt_fields["scheme"] != "https") crt_fields["scheme"] = NULL;
  if (isnull(crt_fields["page"])) crt_fields["page"] = "/";
  var res = http_send_recv3(
    method: "GET",
    transport: crt_fields["scheme"],
    target: crt_fields["host"],
    port: crt_fields["port"],
    item: crt_fields["page"],
    follow_redirect: 3,
    unrestricted_redirect: TRUE
  );

  if (isnull(res) || "200 OK" >!< res[0] || isnull(res[2]))
  {
    dbglog(fname:fname, lvl:1, note:'Failed to download issuer cert');
	  return make_array('ocsp_failure', 'Failed to download issuer cert.');
  }
  var issuer_der_cert = res[2];

  dbglog(fname:fname, lvl:3, note:'Retrieved issuer_der_cert', value:issuer_der_cert);
  # While this should be DER, we've seen PEM in the wild (GoDaddy). Check and
  # convert before sending on
  if ("-----BEGIN CERTIFICATE-----" >< issuer_der_cert)
  {
	  issuer_der_cert = pem_to_blob(issuer_der_cert);
    dbglog(fname:fname, lvl:3, note:'Retrieved issuer_der_cert as blob', value:issuer_der_cert);
  }

  var issuer_parsed_cert = parse_der_cert(cert:issuer_der_cert);
  dbglog(fname:fname, lvl:3, note:'Parsed issuer cert', value:issuer_parsed_cert);
  var ocsp_request;
  ocsp_request = create_ocsp_request(server_der_cert:server_der_cert,
                                     issuer_der_cert:issuer_der_cert);
  dbglog(fname:fname, lvl:2, note:'create_ocsp_request returned', value:ocsp_request);
  if (isnull(ocsp_request)) return NULL;

  if (isnull(ocsp_fields["page"])) ocsp_fields["page"] = "/";
  res = http_send_recv3(
    method: "POST",
    target: ocsp_fields["host"],
    port: ocsp_fields["port"],
    item: ocsp_fields["page"],
    content_type: "application/ocsp-request",
    data: ocsp_request,
    follow_redirect: 3
  );

  if (isnull(res) || isnull(res[2])) 
    return make_array('ocsp_failure', 'OCSP responder failed to respond.');
  dbglog(fname:fname, lvl:3, note:'Received OSCP response', value:res);
  if (response_status_good(ocsp_response:res[2]) != TRUE)
  {
	  return make_array('ocsp_failure',
		  'OCSP responder replied with a bad status: ' + printable_status(ocsp_response:res[2]));
  }

  var revocation_status = 
    get_revocation_status(ocsp_response:res[2], 
                          serial_number:server_parsed_cert["tbsCertificate"]["serialNumber"]);
  var verify_ocsp_response = 
    verify_ocsp_response(ocsp_response:res[2], 
                         issuer_der_cert:issuer_der_cert);
  var ret = make_array('revocation_status', revocation_status, 
                       'verify_ocsp_response', verify_ocsp_response);
  dbglog(fname:fname, lvl:3, note:'Returning', value:ret);
  return ret;
}
