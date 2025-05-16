#TRUSTED 3d77f34102e830bbca36fbba8f1da3a337b9b19d8a17efa760b7a33273aff8a3f2338fe86b13a96c37f651e5af35d26a013d8731907710de97f4f97a99abeb28372ce84b0711d4d2d47661e1cfacd15926b0c06aa58acc838e7c25e59ff58a22d249141db8045c32cc6c0028daf91377d670b5685497bd58effa25118bfe02c8ee6ee2366ca4838065e7bf2313b9ffdffa5644dd6b9c5c03ba822c93ee7d250346aa18a3fdedb4d8cb9b418e360620181954a730d7b239d081c9476b1042972918f42e6684ed4a59c7d3c1e727032a6ea820b6d821aff98199dda6df1eb25d1dfefd5af89627ca79e7c3501ed0ff1bfc0b036c45b44eee0659b95b02844032d8137ce9e398cf6612ed8afcdf7dd8100b03d90a4fc0e81ed3680190432832c9ceae869a21cf4bbba2bf3cbfb933731e0503bee2c747e1c434579609596fbd21bc62782cb9e69f5d4616205ef186f85549bdbbab29ccdbcc467358d540b1e2394c8fe3b1faea960a9906ad700854e7f1b689a67a03a23b8abd89240cf6eb8bc8385e622e7ec26e2d10b6e2e48b237ba477aeee427733acb6057836dd91c51c16d0ecb55da454d7c3ae72cf0faa112ce115a28c2fa6c9eae3241b16c53ced2f9d9f731e2940e5f163f60ec3b4562f5267c8bf1e03e51d083b9c95e74de6905288f9c19af97cf4e63003004df70bf28b8835d58e03c02338626954da3acf89123cc5
#TRUST-RSA-SHA256 857de3254aa4c7796804de38efba42aefe3f3d3a5bed22655fb2b0096b31a9aad57e8f8ae2ad808d246cf726adabfbef4127d132adb8f6c40b4302f29856f415e0bbd7cadf40b71cfab53075005491422439f6dc9dd5b796e9800860c571c0a7371ec7353c48849609c8f1bd7970c6a7603f2a531723c30fff170d7a1455bf2b2a043ca47d472e51b6c8e35360aeda7f749ee92560089a674467dc5ee58cacabb187c576f7288b628504c947cab46bac20110f913ed7dcedb3c9f167e587b770c02012ebf457e38ea7a08b3927c6d4c7a8e3e284272e5a71656d70eda87dfb28366d3076467a4cacea6601a4dbae52f6e36e7c9c5b06879d9d88488794f2437d07052cd393d5e2993d9ac812f0f2773cf33f389f8a4d6652504b3f25facbdf9b3f26151f59454f4cf7ee37b405b610885d787f9835e9859c6edb4a98a9102d215d107f0796e8fee4efe1005202d34f8939554e0b59117cd18218f3749a246538e2392f5a2ef25740a8295918741afe90372d987a7b258fd8aaf5ed2607358a509d12d7154535adec6a0e36db492740345c2a8e01ea2f55bd700d9c8810831c76287659400c307f81b5c8635ff996328f51ae9b94c82a6c0ab5f535060b212b54dd454870a9f2fe673e8f8af768ac87a83c7d0a0314c0d5413457cdc5a9b9ec7209243b42b1dfd191001bfac874bd017771e8b99accb328f2b572668deec108f6
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# ssh_globals.inc
#
# Revision: 1.3
#

include("compat_shared.inc");
include("byte_func.inc");
include("base64.inc");
include("debug.inc");
include("spad_log_func.inc");

global_var checking_default_account_dont_report;
global_var last_error, _ssh_error;

global_var USE_SSH_WRAPPERS = TRUE;

global_var INFO_LOCAL, INFO_SSH, INFO_RSH, INFO_REXEC, INFO_RLOGIN, INFO_TELNET;
INFO_LOCAL  = 1;
INFO_SSH    = 2;
INFO_RSH    = 3;
INFO_REXEC  = 4;
INFO_RLOGIN = 5;
INFO_TELNET = 6;

# accept-list pattern, will exclude non-English chars but allow *
global_var NO_INJECTION_PATTERN = "^(( *[*A-Za-z0-9_./\[\]][*A-Za-z0-9_.\-/\[\]]*)|" +
                                  "('[*A-Za-z0-9_.\-/\[\] ]*')|" +
                                  '("[*A-Za-z0-9_.\\-/\\[\\] ]*"))$';
# deny-list pattern
global_var INJECTION_PATTERN =  "[\\\{\}\$&\|;\(\)<>@!\*`'%#]";
##
# Checks to see if we're using the ssh_compat/ssh_lib wrappers (returns TRUE)
# or the legacy code (returns FALSE). Just a simple getter for now, but this is
# where we can add any additional compatibility checks to help us make that
# decision.
##
function using_ssh_wrappers()
{
  return USE_SSH_WRAPPERS && nasl_level() >= 6000;
}

#-----------------------------------------------------------------#
# Set SSH debugging error msg                                     #
#-----------------------------------------------------------------#
function set_ssh_error(msg)
{
  if(using_ssh_wrappers())
    last_error = msg;
  _ssh_error = msg;

  if(msg)
  {
    var name = ((SCRIPT_NAME - ".nasl") - ".nbin") + "_ssh_pkt.log";
    dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:msg, name:name);
  }
}


##
# Parses a length-prefixed string from the buffer.
#
# @param buffer Buffer to parse.
# @param pos Position from which to parse.
#
# @return NULL on error, parsed string otherwise.
##
function getstring(buffer, pos)
{
  local_var len;

  if (pos + 4 > strlen(buffer))
    return NULL;

  len = ntol(buffer:buffer, begin:pos);
  if (isnull(len))
    return NULL;

  pos += 4;
  if (pos + len > strlen(buffer))
    return NULL;

  if (len == 0)
    return "";

  return substr(buffer, pos, pos + len - 1);
}

##
# Creates a variable-length string field for an SSH packet.
#
# @param buffer String to put in field.
#
# @remark The buffer parameter may also be given anonymously.
#
# @return The input string prepended by its 32-bit length.
##
function putstring(buffer)
{
  if (isnull(buffer))
    buffer = _FCT_ANON_ARGS[0];

  return raw_int32(strlen(buffer)) + buffer;
}

##
# Retrieves an mpint encoded value from a byte buffer.
#
# @param buffer A string of byte values
# @param pos    Position in the buffer to start reading
#
# @return Returns a mpint encoded value from the buffer as
#         an array with a length and raw byte string.
##
function getmpint(buffer, pos)
{
  local_var len, ret, first;
  ret = make_array();

  if(pos + 4 > strlen(buffer))
    return NULL;
  len = getdword(blob:buffer, pos:pos, order:BYTE_ORDER_BIG_ENDIAN);
  if(isnull(len))
    return NULL;
  if(len == 0)
    return "";
  pos += 4;
  if(pos + len > strlen(buffer))
    return NULL;

  ret['value'] = substr(buffer, pos, pos + len - 1);
  ret['length'] = strlen(ret['value']) + 4;

  first = getbyte(blob:ret['value'], pos:0);

  if(first == 0)
  {
    ret['value'] = substr(ret['value'], 1);
  }

  return ret;
}

##
# Determines if the given key type is a valid OpenSSH certificate type
#
# @remark for valid key types, see http://www.openssh.com/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL.certkeys
# @anonparam key_type key type to check
# @return TRUE if "key_type" is a valid OpenSSH certificate type,
#         FALSE otherwise
##
function _is_valid_openssh_cert_type()
{
  local_var key_type;
  key_type = _FCT_ANON_ARGS[0];

  # v00 was replaced with v01 in OpenSSH 5.6. v00 will be deprecated, but it is possible some clients/servers are still using it
  return
    key_type == 'ssh-rsa-cert-v00@openssh.com' ||
    key_type == 'ssh-dss-cert-v00@openssh.com' ||
    key_type == 'ssh-rsa-cert-v01@openssh.com' ||
    key_type == 'ssh-dss-cert-v01@openssh.com' ||
    key_type == 'ecdsa-sha2-nistp256-cert-v01@openssh.com' ||
    key_type == 'ecdsa-sha2-nistp384-cert-v01@openssh.com' ||
    key_type == 'ecdsa-sha2-nistp521-cert-v01@openssh.com' ||
    key_type == 'ssh-ed25519-cert-v01@openssh.com';
}

##
# Parse public key only.
#
# @remark See RFC 4462 for details.
#
# @param pub Public key or certificate.
# @param iscred This key is a SSH credential.
#
# @return Array of key information.
##
function ssh_parse_public_key_only(pub, iscred)
{
  local_var blob, errmsg, key, line, lines, next, nonce, tmp;

  if(isnull(iscred)) iscred = TRUE;

  if ("---" >< pub)
  {
    # Parse key formatted in the SSH Public Key File Format.
    blob = "";
    lines = split(pub, sep:'\n', keep:FALSE);

    foreach line (lines)
    {
      # Skip lines that aren't part of the key itself.
      if ("---" >< line || ":" >< line)
        continue;

      # Remove DOS-style line ending remnants.
      if ('\r' >< line)
        line -= '\r';

      blob += line;
    }
  }
  else
  {
    # Parse key formatted in the OpenSSH public key file format.
    blob = ereg_replace(
      pattern : "[^ ]* ([^ ]*)( .*)?$",
      string  : chomp(pub),
      replace : "\1"
    );
  }

  # Convert to binary form.
  if (strlen(blob)) blob = base64decode(str:blob);
  if (strlen(blob) == 0)
  {
    if(iscred)
    {
      errmsg = "Nessus failed to parse the public key.";
      dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:"The deprecated SSH library could not parse the SSH key");
    }
    return NULL;
  }

  # Initialize key structure.
  key = make_array("pub", blob);

  # Parse type of key.
  key["type"] = getstring(buffer:blob, pos:0);
  next = 4 + strlen(key["type"]);

  # if this is a certificate, skip over the nonce field if necessary.
  # in v00 the nonce is several fields after the relevant RSA and DSA data, but
  # in v01 the nonce is right after the key type
  # for info on the formats, see the different revisions of http://www.openssh.com/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL.certkeys
  # this is a quick solution (done in lieu of actually parsing the certificate) but it works
  if (_is_valid_openssh_cert_type(key["type"]) && key["type"] !~ '-cert-v00@openssh.com$')
  {
    nonce = getstring(buffer:blob, pos:next);
    next += 4 + strlen(nonce);
  }

  if ("ssh-rsa" >< key["type"])
  {
    # Store the signature algorithm.
    key["alg"] = "ssh-rsa";

    # Parse exponent from RSA key.
    tmp = getmpint(buffer:blob, pos:next);
    if(isnull(tmp) || empty_or_null(tmp['value']) || isnull(tmp['length']))
    {
        set_ssh_error(msg:"Error getting RSA.e from cert.");
        return NULL;
    }
    key['e'] = tmp['value'];
    next += tmp['length'];

    # Parse modulus from RSA key.
    tmp = getmpint(buffer:blob, pos:next);
    if(isnull(tmp) || empty_or_null(tmp['value']) || isnull(tmp['length']))
    {
        set_ssh_error(msg:"Error getting RSA.n from cert.");
        return NULL;
    }
    key['n'] = tmp['value'];
    next += tmp['length'];
  }
  else if ("ssh-dss" >< key["type"])
  {
    # Store the signature algorithm.
    key["alg"] = "ssh-dss";

    # Parse 'p' parameter from DSA key.
    tmp = getmpint(buffer:blob, pos:next);
    if(isnull(tmp) || empty_or_null(tmp['value']) || isnull(tmp['length']))
    {
        set_ssh_error(msg:"Error getting DSA.p from cert.");
        return NULL;
    }
    key['p'] = tmp['value'];
    next += tmp['length'];

    # Parse 'q' parameter from DSA key.
    tmp = getmpint(buffer:blob, pos:next);
    if(isnull(tmp) || empty_or_null(tmp['value']) || isnull(tmp['length']))
    {
        set_ssh_error(msg:"Error getting DSA.q from cert.");
        return NULL;
    }
    key['q'] = tmp['value'];
    next += tmp['length'];

    # Parse 'g' parameter from DSA key.
    tmp = getmpint(buffer:blob, pos:next);
    if(isnull(tmp) || empty_or_null(tmp['value']) || isnull(tmp['length']))
    {
        set_ssh_error(msg:"Error getting DSA.g from cert.");
        return NULL;
    }
    key['g'] = tmp['value'];
    next += tmp['length'];

    # Parse 'y' parameter from DSA key.
    tmp = getmpint(buffer:blob, pos:next);
    if(isnull(tmp) || empty_or_null(tmp['value']) || isnull(tmp['length']))
    {
        set_ssh_error(msg:"Error getting DSA.y from cert.");
        return NULL;
    }
    key['y'] = tmp['value'];
  }
  else
  {
    if(iscred)
      dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:"The SSH public key is not supported by the deprecated SSH library.");

    return NULL;
  }

  return key;
}


