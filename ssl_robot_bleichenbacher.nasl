#TRUSTED 845100c6b5abc5f660bbc846c08efea12ee8ee7a6496c64a9452150f781c3fbbae29e71018127e23f298f70d1b43fc95e87571ae4a5e61db208eb35451d55776d59f0c22f383ccc89c3bf5d84903485e2cccdb0c85fa665b9f25c2d4033a3bb9079175adb4ee12788f5f9aae46d21bad42abd4d6c93a2378bbb75361a08672f972b37efcd96ebcdcaa415539cf0bce78bc6f5b5302b46ad228c950ad270fb5ba6d04fc14d85123f7105790c36a36d0ad0e3d99e6a9a14fde29c087b5120dc76dbd41745e381a8375c1bc144e376fc7059d95af8275205bbbadc60133f601efcb3b56709a1886b7b90626eaed4dbf3d069b3e2ea94b378147389dd8dc9b48fbd47bcda2b8ef4f4866696d59c11d2e3dbb2ec4447db46e63561e6425975b886a8f52d6e231120dadcc6af982be77f9a3f8c0cb172f3eb80c84ad4d7b37c7c771c9e5ca0ade3656a3ea9f6db212d2f8f6748db119eb54a20d81a428dfb6174c9d572a928685048a6eeeb5d9df4ba3062bef1f51cc3b432ff764dd6c8f9840800740129ed74fabe85912c4cb1e1b799af34a2cc87b87fb1c7d47ebd632f18dcb3064764c8a5df27057658025ed12d71034292b0d55d95b159b98f9e6de87165b7d661dd36a3672e50e748dd759c20e97969016434fee57e80406f0be822237bfccd842cdb2c72dfc9e7b91f4d375342046ad73b5609e1ec72bc5346579869630b6b9
#TRUST-RSA-SHA256 98699b3e1966d5bbb526568458acf7b895c6473d8144a0e73bc8c095a401fed2102c29bdbe73960dc0c7fc14ecf424bb36db9816862a130e5479fea9befd673b033bf823c11f85a96d72e44e176ef6feda41e28c0bdff46e486a1f81f241db53066d6a95c04abee43a630fe94daa630b7e2cca71c78b7e512e5d0a7b576933bb71372dab30970b5d025b7e2e56f5b7f3c108d3b122de90fdb7cccdc77a36e151590c3060f2558b0d1065fb07827ce80374fee7c12599377853f8ab330d41a9f247056f0b47a6c66b4dabf18d6567629d65045aae729dd21a647a1a532e7f94cb9b99eb66fd40ecca4572f3979c903d325cbfb9a8252e08617858150cac0d1a3120e1df4b1a679de69071f3c9a72fca32bf1d2d52746b9cd97e6370d58ad08d97a584a1a46d40118b2d834a9b19b883a36e462fcc8bb639132664b0da53c96657d80a4ed9f923e97a25c1d2acc53df7c926635d82d9de1b4f70a00318520f9876e867426e16cfb39b0884fafce3d9cb024c9b6c9e06ef3bab63c2d4700b5dcc7a9e5d4004fe04d95576b66a10413ca90bd827c9a1e95a1c8253eb3fe3b33d1140bd237d0534149df0340ce6c9985e7e6b17b476055f745192a691f191e3521ab3f40a35313a5b246b751b3fc1b4f0752adf38abc99525023c85acfbad85aeeb7a3d47c4510b307ef8bfd78a83fd8d02ea7514568d77c1581f15dfcdcc21fcaf8d
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(105415);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/24");

  script_cve_id(
    "CVE-2012-5081",
    "CVE-2016-6883",
    "CVE-2017-6168",
    "CVE-2017-12373",
    "CVE-2017-13098",
    "CVE-2017-13099",
    "CVE-2017-17382",
    "CVE-2017-17427",
    "CVE-2017-17428",
    "CVE-2017-1000385"
  );

  script_name(english:"Return Of Bleichenbacher's Oracle Threat (ROBOT) Information Disclosure");

  script_set_attribute(attribute:"synopsis", value:
"The server leaks whether or not an RSA-encrypted ciphertext is
formatted correctly.");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by an information disclosure
vulnerability. The SSL/TLS service supports RSA key exchanges, and
incorrectly leaks whether or not the RSA key exchange sent by a client
was correctly formatted. This information can allow an attacker to
decrypt previous SSL/TLS sessions or impersonate the server.

Note that this plugin does not attempt to recover an RSA ciphertext,
however it sends a number of correct and malformed RSA ciphertexts as
part of an SSL handshake and observes how the server responds.

This plugin attempts to discover the vulnerability in multiple ways,
by not completing the handshake and by completing it incorrectly, as
well as using a variety of cipher suites. Only the first method that
finds the service to be vulnerable is reported.

This plugin requires report paranoia as some services will
report as affected even though the issue is not exploitable.");
  script_set_attribute(attribute:"see_also", value:"https://robotattack.org/");
  script_set_attribute(attribute:"see_also", value:"https://support.f5.com/csp/article/K21905460");
  script_set_attribute(attribute:"see_also", value:"https://support.citrix.com/article/CTX230238");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20171212-bleichenbacher
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?953be8c5");
  script_set_attribute(attribute:"see_also", value:"http://erlang.org/pipermail/erlang-questions/2017-November/094257.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a patched version of the software. Alternatively, disable
RSA key exchanges.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-17428");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2017-6168");
  script_set_attribute(attribute:"cvss3_score_rationale", value:"Scoring adjustsed to align with CVSS 3.1 attack complexity guidance.");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/12/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2017-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssl_supported_versions.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("SSL/Supported");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("x509_func.inc");
include("rsync.inc");
include("ftp_func.inc");
include("ldap_func.inc");
include("nntp_func.inc");
include("smtp_func.inc");
include("telnet2_func.inc");
include("ssl_funcs.inc");
include("string.inc");
include("spad_log_func.inc");

# Paranoia added as some services are not exploitable
if (report_paranoia < 2) audit(AUDIT_PARANOID);

##
# Checks whether a cipher is in a list of cipher suites.
#
# @anonparam cipher Cipher in question.
# @anonparam ciphers List of cipher suites.
#
# @return TRUE for success, FALSE otherwise.
##
function tls_cipher_in_list()
{
  local_var cipher, ciphers, i, id, len;

  cipher = _FCT_ANON_ARGS[0];
  ciphers = _FCT_ANON_ARGS[1];

  len = strlen(ciphers);
  for (i = 0; i < len; i += 2)
  {
    id = substr(ciphers, i, i + 2 - 1);
    if (cipher == id) return TRUE;
  }

  return FALSE;
}

PREMASTER_TYPE_CORRECT           = 2;
PREMASTER_TYPE_WRONG_FIRST_BYTES = 3;
PREMASTER_TYPE_WRONG_ZERO_POS    = 4;
PREMASTER_TYPE_MISSING_ZERO      = 5;
PREMASTER_TYPE_WRONG_VERSION     = 6;
function make_premaster(modulus_length, premaster_type)
{
  local_var pad_length, premaster;
  # See https://tools.ietf.org/html/rfc2246#section-7.4.7.1
  # PKCS#1 v1.5 format: [2 header bytes + nonzero padding + 0x00 byte + 2-byte version + 46-byte premaster]
  pad_length = (modulus_length - 2 - 1 - 2 - 46);
  premaster = "nessusnessusnessusnessusnessusnessusnessusness";

  switch (premaster_type)
  {
    case PREMASTER_TYPE_CORRECT:
      return '\x00\x02' + crap(data:'N', length:pad_length) + '\x00\x03\x03' + premaster;
    case PREMASTER_TYPE_WRONG_FIRST_BYTES:
      return '\x05\x05' + crap(data:'N', length:pad_length) + '\x00\x03\x03' + premaster;
    case PREMASTER_TYPE_WRONG_ZERO_POS:
      return '\x00\x02' + crap(data:'N', length:pad_length) + '\xff' + premaster + '\x00\x11';
    case PREMASTER_TYPE_MISSING_ZERO:
      return '\x00\x02' + crap(data:'N', length:pad_length) + '\xff\x03\x03' + premaster;
    case PREMASTER_TYPE_WRONG_VERSION:
      return '\x00\x02' + crap(data:'N', length:pad_length) + '\x00\x05\x05' + premaster;
  }
}

##
# We don't generate the premaster ahead of time, in case the
# server sends a different RSA certificate depending on ciphersuite.
##
function attack(port, ciphers, premaster_type, send_tls_finished_msg)
{
  local_var soc, data, rec, srv_random, clt_random, version, cipher_desc;
  local_var cert, clt_cert_requested, skex, n, e, dh_privkey;
  local_var ckex, keyblk, tls_keys, tls_ciphertext, pubkey, ivlen, maclen, blocklen;
  local_var result, bpf, packet, err, ip_header_size, tcp_header, fin, rst;
  local_var loop_count;

  # Get a socket to perform a handshake.
  soc = open_sock_ssl(port);
  if (!soc)
    return [FALSE, "open_sock_ssl", "Couldn't begin SSL handshake"];

  data = client_hello(
    v2hello:FALSE,
    version:mkword(SSL_V3), # Record-layer version (RFC5246 Appendix E)
    maxver:mkword(TLS_12),  # Handshake version; maximum we support
    cipherspec:ciphers,
    extensions:tls_ext_sni(hostname:get_host_name())
  );
  # Send the ClientHello
  send(socket:soc, data:data);

  # Read records one at a time. Expect to see at a minimum:
  # ServerHello, Certificate, and ServerHelloDone.
  loop_count = 0;
  while (TRUE)
  {
    if (loop_count++ > 50)
      exit(1, "Exceeded maximum number of loops while waiting for server's first flight of messages.");

    # Receive a record from the server.
    data = recv_ssl(socket:soc);
    if (isnull(data))
    {
      close(soc);
      return [FALSE, "recv_ssl", "Did not receive an expected SSL message from the server"];
    }

    # ServerHello: Extract the random data for computation of keys.
    rec = ssl_find(
      blob:data,
      'content_type', SSL3_CONTENT_TYPE_HANDSHAKE,
      'handshake_type', SSL3_HANDSHAKE_TYPE_SERVER_HELLO
    );
    if (!isnull(rec))
    {
      # If server asks for version less than SSLv3 or higher than TLS 1.2, fail.
      if (rec['handshake_version'] < SSL_V3 || rec['handshake_version'] > TLS_12)
        return [FALSE, "handshake_version", "Server selected a TLS version we don't support"];

      # Use the TLS version the server wants
      version = rec['handshake_version'];

      srv_random = mkdword(rec['time']) + rec['random'];

      # Wacko SSL servers might return a cipher suite not in the
      # client's request list.
      if (!tls_cipher_in_list(mkword(rec['cipher_spec']), ciphers))
      {
        close(soc);
        return [FALSE, "cipher_spec", "Server ignored our list of supported ciphers"];
      }

      # Store the negotiated cipher suite.
      cipher_desc = ciphers_desc[cipher_name(id:rec['cipher_spec'])];

      if (isnull(cipher_desc))
      {
        close(soc);
        return [FALSE, "cipher_spec", "Assertion failure"];
      }
    }

    # Certificate: Extract the server's public key.
    rec = ssl_find(
      blob:data,
      'content_type', SSL3_CONTENT_TYPE_HANDSHAKE,
      'handshake_type', SSL3_HANDSHAKE_TYPE_CERTIFICATE
    );
    if (!isnull(rec) && max_index(rec['certificates']) > 0)
    {
      # First cert in the chain should be the server cert.
      cert = parse_der_cert(cert:rec['certificates'][0]);
      if (isnull(cert))
      {
        close(soc);
        return [FALSE, "parse_der_cert", "Failed to parse server's certificate"];
      }
      cert = cert['tbsCertificate'];
    }

    # Server Key Exchange.
    # Normally RSA handshakes don't have this, but we can check EXPORT ciphers this way.
    rec = ssl_find(
      blob:data,
      'content_type', SSL3_CONTENT_TYPE_HANDSHAKE,
      'handshake_type', SSL3_HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE
    );
    if (!isnull(rec['data']))
      skex = ssl_parse_srv_kex(blob:rec['data'], cipher:cipher_desc, version:version);

    # Certificate Request.
    rec = ssl_find(
      blob:data,
      'content_type', SSL3_CONTENT_TYPE_HANDSHAKE,
      'handshake_type', SSL3_HANDSHAKE_TYPE_CERTIFICATE_REQUEST
    );
    if (!isnull(rec['data']))
      clt_cert_requested = TRUE;

    # Server Hello Done.
    rec = ssl_find(
      blob:data,
      'content_type', SSL3_CONTENT_TYPE_HANDSHAKE,
      'handshake_type', SSL3_HANDSHAKE_TYPE_SERVER_HELLO_DONE
    );
    # When we get a ServerHelloDone, it's our turn to send again.
    if (!isnull(rec))
      break;

    # Is it an alert?
    rec = ssl_find(
      blob:data,
      encrypted:FALSE,
      'content_type', SSL3_CONTENT_TYPE_ALERT
    );
    if (!isnull(rec))
    {
      close(soc);
      return [FALSE, "handshake_failure", "Server sent alert to ClientHello. Level: " + rec['level'] + ", description: " + rec['description']];
    }
  }

  data = '';
  # Create an empty client certificate if one is requested.
  if (clt_cert_requested)
  {
    # Send an empty certificate for now. TLSv1.0 says the client can
    # send an empty certificate.
    data += ssl_mk_record(
      type:SSL3_CONTENT_TYPE_HANDSHAKE,
      version:version,
      data:ssl_mk_handshake_msg(
        type : SSL3_HANDSHAKE_TYPE_CERTIFICATE,
        data : ssl_vldata_put(data:NULL,len:3)
      )
    );
  }

  # Process ServerCertificate and ServerKeyExchange messages.
  if (cipher_field(name:cipher_desc, field:"kex") !~ "RSA($|\()")
  {
    close(soc);
    return [FALSE, "kx", "Unsupported key exchange method"];
  }

  if (isnull(cert))
  {
    close(soc);
    return [FALSE, "rsa_kx", "Server selected RSA key exchange but didn't provide a certificate"];
  }

  if (isnull(cert['subjectPublicKeyInfo']) || isnull(cert['subjectPublicKeyInfo'][1]))
  {
    close(soc);
    return [FALSE, "rsa_kx", "A server certificate with an unsupported algorithm was found."];
  }

  n = cert['subjectPublicKeyInfo'][1][0];
  e = cert['subjectPublicKeyInfo'][1][1];

  if (isnull(n) || isnull(e))
  {
    close(soc);
    return [FALSE, "rsa_kx", "Failed to extract public key from server certificate."];
  }

  # Round-trip the modulus to get rid of any leading zeroes.
  n = bn_hex2raw(bn_raw2hex(n));

  # Encrypt the premaster secret with server's RSA public key.
  ckex = bn_mod_exp(make_premaster(modulus_length:strlen(n), premaster_type:premaster_type), e, n);
  ckex = ssl_vldata_put(data:ckex, len:2);

  # Create a ClientKeyExchange record
  data += ssl_mk_record(
    type:SSL3_CONTENT_TYPE_HANDSHAKE,
    version:version,
    data:ssl_mk_handshake_msg(
      type:SSL3_HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE,
      data:ckex
    )
  );

  if (send_tls_finished_msg)
  {
    data += tls_mk_record(
      type:SSL3_CONTENT_TYPE_CHANGECIPHERSPEC,
      data:mkbyte(1),
      version:version
    );

    # Figure out IV, MAC, and padding length of the cipher we're using.  If we
    # send an incorrectly-sized Finished message, the server can reject us
    # without ever attempting to decrypt it, and we don't want this. We want it
    # to look legitimate and for the server to give us it's real "decryption
    # failed" alert.
    var encrypt = cipher_field(name:cipher_desc, field:"encrypt");
    if ("AES-GCM" >< encrypt)
    {
      ivlen = 8;
      maclen = 16;
      # AES-GCM uses AES-CTR under the hood; it's a stream cipher
      blocklen = 1;
    }
    else
    {
      if ("3DES-CBC" >< encrypt || "DES-CBC" >< encrypt)
        blocklen = 8;
      else if ("AES-CBC" >< encrypt)
        blocklen = 16;
      # Used in China
      else if ("Camellia" >< encrypt)
        blocklen = 16;
      # Used in South Korea
      else if ("SEED-CBC" >< encrypt)
        blocklen = 16;
      # Safe guess; SSL implementations check that a ciphertext is divisible by the block length.
      # DES block length (8) and AES and CAMELLIA block length (16) both evenly divide 16.
      else
        blocklen = 16;

      # These CBC ciphers all use an IV length that's the same as the block length
      ivlen = blocklen;

      # MAC will be either SHA256 or SHA1. There are no SHA384 ciphersuites using a CBC-mode cipher.
      if ("SHA256" >< cipher_field(name:cipher_desc, field:"mac"))
        maclen = 32;
      else
        maclen = 20;
    }

    # Make a fake Finished message. This is designed to trigger a bad_record_mac
    # or similar TLS alert. The encrypted "finished hash" is 12 bytes, so we
    # start with that. We tack on a fake MAC, and round up to the nearest block
    # size as if it were properly encrypted.
    tls_ciphertext = ssl_mk_handshake_msg(type:SSL3_HANDSHAKE_TYPE_FINISHED, data:crap(data:'Finished', length:12));
    # Tag on the fake MAC
    tls_ciphertext += crap(data:'Mac', length:maclen);
    # Add on some bytes to satisfy padding length requirements, if it's a block cipher
    if (blocklen > 1)
      tls_ciphertext += crap(data:'Padding', length:blocklen - (strlen(tls_ciphertext) % blocklen));

    # Add on an explicit IV if we're using TLS v1.1 or higher
    if (version >= TLS_11)
      tls_ciphertext = crap(data:'Iv', length:ivlen) + tls_ciphertext;

    data += tls_mk_record(
      type:SSL3_CONTENT_TYPE_HANDSHAKE,
      data:tls_ciphertext,
      version:version
    );
  }

  if (isnull(soc) || port <= 0 || get_source_port(soc) <= 0)
    exit(1, "Invalid socket for a packet capture instance (dest port "+string(get_source_port(soc))+", src port "+string(port)+").");

  # Try to catch the server closing the connection. We want to catch either an RST or a FIN.
  bpf = bpf_open(
    'tcp and src port ' + port +
    ' and src host ' + get_host_ip() +
    ' and dst host ' + compat::this_host() +
    ' and dst port ' + get_source_port(soc) +
    ' and tcp[tcpflags] & (tcp-fin|tcp-rst) != 0'
  );
  if (!bpf)
    exit(1, "Couldn't open a packet capture instance.");

  # Send the TLS messages
  # If we're using the full handshake this will be ClientKeyExchange + ChangeCipherSpec + Finished
  # If we're using the abbbreviated handshake this will be just ClientKeyExchange
  send(socket:soc, data:data);

  # The "fingerprint" of the server's behaviour for this one probe
  result = [];

  # The effect of this loop is to receive as many times as possible and store
  # all the TLS records received. Allegedly, some implementations will send
  # more than TLS alert (!?).
  # At the end when nothing more can be received, we check why; did the server
  # leave the connection open and just stop sending, or close with a FIN or
  # RST? And then add that onto the end of the list.
  # The idea is this becomes a "fingerprint" of the server's behaviour, and
  # then we can compare fingerprints from the different types of malformed
  # premaster secret and see if an oracle exists.
  loop_count = 0;
  while (TRUE)
  {
    if (loop_count++ > 50)
      exit(1, "Exceeded maximum number of loops while waiting for server's response to tampered RSA key exchange.");

    # Receive a record from the server.
    # Set the timeout explicitly, because we don't want to be affected by the
    # Nessus's check_read_timeout setting.
    data = recv_ssl(socket:soc, timeout:5);
    if (isnull(data))
    {
      if (socket_get_error(soc) == ETIMEDOUT)
      {
        result[max_index(result)] = "server waited";
      }
      else if (socket_get_error(soc) == ECONNRESET)
      {
        # Try to tell apart FIN and RST
        packet = bpf_next(bpf:bpf, timeout:0);
        if (isnull(packet))
        {
          err = "Did not receive an expected FIN or RST packet from port " + port;
        }
        else
        {
          if (TARGET_IS_IPV6)
            ip_header_size = 40;
          else
            ip_header_size = 20;
          # Carve out the TCP header
          tcp_header = substr(packet, 14 + ip_header_size, 14 + ip_header_size + 20);
          fin = ord(tcp_header[13]) & 1;
          rst = ord(tcp_header[13]) & 4;
          if (fin)
            result[max_index(result)] = "server sent TCP FIN";
          else if (rst)
            result[max_index(result)] = "server sent TCP RST";
          else
          {
            err = "Did not receive an expected FIN or RST packet from port " + port;
          }
        }
      }
      else
      {
        err = "Unexpected socket error status after receiving: " + socket_get_error(soc);
      }

      bpf_close(bpf);
      close(soc);

      if (err)
        exit(1, err + ".");
      else
        break;
    }

    # Is it an alert?
    rec = ssl_find(
      blob:data,
      encrypted:FALSE,
      'content_type', SSL3_CONTENT_TYPE_ALERT
    );
    if (!isnull(rec))
      result[max_index(result)] = "server sent TLS alert " + string(rec['description']);
  }
  return result;
}

get_kb_item_or_exit('SSL/Supported');
# Get a port that uses SSL.
port = get_ssl_ports(fork:TRUE);
if (isnull(port))
  exit(1, 'The host does not appear to have any SSL-based services.');

# Find out if the port is open.
if (!get_port_state(port))
  audit(AUDIT_PORT_CLOSED, port, "TCP");

# CBC ciphers that don't use AES
cipher_list_cbc_not_aes =
  ciphers['TLS1_CK_RSA_WITH_3DES_EDE_CBC_SHA'] +
  ciphers['TLS1_CK_RSA_WITH_CAMELLIA_128_CBC_SHA'] +
  ciphers['TLS1_CK_RSA_WITH_CAMELLIA_256_CBC_SHA'] +
  ciphers['TLS1_CK_RSA_WITH_SEED_CBC_SHA'];

# Just AES-CBC ciphers
cipher_list_aes_cbc =
  ciphers['TLS1_CK_RSA_WITH_AES_128_CBC_SHA'] + # <- Required by all TLS 1.2 impls.
  ciphers['TLS1_CK_RSA_WITH_AES_256_CBC_SHA'] +
  ciphers['TLS1_RSA_WITH_AES_128_CBC_SHA256'] +
  ciphers['TLS1_RSA_WITH_AES_256_CBC_SHA256'];

# Just AES-GCM ciphers
cipher_list_gcm =
  ciphers['TLS12_RSA_WITH_AES_128_GCM_SHA256'] +
  ciphers['TLS12_RSA_WITH_AES_256_GCM_SHA384'];

# This just collects the responses for all the premasters and returns them.
# If there was a handshake error or if the responses were all the same,
# NULL is returned.
function try_with_all_premasters(cipher_list, port, send_tls_finished_msg)
{
  local_var response, responses, premasters, premaster, correct_premaster_reponse;

  premasters = [
    PREMASTER_TYPE_CORRECT,
    PREMASTER_TYPE_WRONG_FIRST_BYTES,
    PREMASTER_TYPE_WRONG_ZERO_POS,
    PREMASTER_TYPE_MISSING_ZERO,
    PREMASTER_TYPE_WRONG_VERSION
  ];

  spad_log(message:"Port: " + port + ", ciphers: " + hexstr(cipher_list) + ", send_tls_finished_msg: " + int(send_tls_finished_msg) + ".");
  responses = [];
  foreach premaster (premasters)
  {
    response = attack(
      port:port,
      ciphers:cipher_list,
      premaster_type:premaster,
      send_tls_finished_msg:send_tls_finished_msg
    );
    # The return value is like [FALSE, "step", "human-readable message"] when
    # there's a connection error.
    # If there was a connection error it's probably because the server doesn't
    # support the ciphers we tried with, so bail out early here.
    if (typeof(response[0]) == "int" && response[0] == FALSE)
    {
      spad_log(message:"Connection failed: " + response[2] + ".");
      return NULL;
    }

    responses[len(responses)] = response;
  }
  spad_log(message:"All premasters tested. Ciphers appear supported.");

  foreach response (responses)
  {
    # If the server replied differently to any of the malformed premasters
    # that we tried, compared to the correctly-formatted premaster, then
    # the server is vulnerable.
    correct_premaster_reponse = responses[0];
    if (!equals(correct_premaster_reponse, response))
      return responses;
  }

  # All the responses were the same. Server isn't vulnerable to this particular attack.
  return NULL;
}

# We'll try with the full handshake first. It's faster, because we always end
# with sending an invalid encrypted Finished message, which the server can
# respond to immediately.
# When we don't send a Finished and stop after sending the ClientKeyExchange,
# the *correct* thing for the server to do is to wait and so we'll end up
# waiting a lot.
foreach send_tls_finished_msg ([TRUE, FALSE])
{
  foreach cipher_list ([cipher_list_gcm, cipher_list_aes_cbc + cipher_list_cbc_not_aes])
  {
    responses = try_with_all_premasters(
      cipher_list:cipher_list,
      port:port,
      send_tls_finished_msg:send_tls_finished_msg
    );
    # We get back null if the server isn't vulnerable with these
    # ciphers, or if the server didn't support them at all.
    if (isnull(responses))
      continue;

    # We got back a list of responses. Try the same attack once more and compare
    # the responses to the first attempt. If they're the same, then the server
    # is vulnerable.
    # We try twice because this is what the other detection tools do, and it makes
    # sense because some of the oracles rely on the server timing out.
    responses2 = try_with_all_premasters(
      cipher_list:cipher_list,
      port:port,
      send_tls_finished_msg:send_tls_finished_msg
    );
    # This does a deep equality check.
    if (equals(responses2, responses))
    {
      if (send_tls_finished_msg)
        attack_type = "sent a TLS Finished message with incorrect padding";
      else
        attack_type = "waited, without sending a TLS Finished message";

      report =
        '\nThe test sent a crafted RSA ciphertext and then ' + attack_type + '.' +
        '\nThe following differences in behaviour were seen by Nessus :' +
        '\n  - As a baseline with correct formatting : ' + join(responses[0], sep:', ') +
        '\n  - With incorrect leading bytes          : ' + join(responses[1], sep:', ') +
        '\n  - With the 0x00 byte in incorrect place : ' + join(responses[2], sep:', ') +
        '\n  - With the 0x00 byte missing            : ' + join(responses[3], sep:', ') +
        '\n  - With an incorrect version number      : ' + join(responses[4], sep:', ');
      security_report_v4(
        port:port,
        extra:report,
        severity:SECURITY_HOLE
      );
      exit(0);
    }
  }
}
exit(0, "The SSL/TLS service at port " + port + " does not appear to be vulnerable.");

