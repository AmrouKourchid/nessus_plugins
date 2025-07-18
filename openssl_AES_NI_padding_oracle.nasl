#TRUSTED 16fc5b3ce7b0301b242cd71d5f7f4b233fe787bf1f0dc962d794896a64139e2f58597101d1f12b97371ecf4aaa1912546db4ee09dc20174b5de24ee285c19ab1531fbf70914a898bc1dc8bf0f94eebd827488d67eb4a981fbd0f3be0857814c425a090b257261427486577fcf0b5e025b5716a5893acf6ad61afeaa19394fc25709ce9ce4089dd997a776fdd41fb8e876537a47e11ad3f982d08144731664d7425a53684ed1b9e26d9a4a2b3ab76c658cef6a371a485acb5c55a4fb60d7451212e18f344c59d9c4a88ca0e0aa741a81aad8fbd7e6fb1648d3b2e721eea6bf6a3dc56492f715c56b84931e9755ee4253017b7cf525a0a4137c500125e324a6f31c21688699802d1e767f937e0d1c669e4a3b267db0dabdec6a43402be1e589e55fdfcb442051f26ea5289010dec4de77ae9a6cb7c53a063ff8a26ffb379ea20b42ded713b321c4745e8c7ccc94a863e83e059b74647d3f8b5fbbeb92927d664d6e589651af4969f5dfdc494b2938565a92da80cbdf39bf7d060a242fce9999a6648dfa1ea7c07fd2bda517abb09ddae2f5fcb3d1f7eff70596437f8ae51b871346c8f22ccb4a24f8abbaaf468c7e88a31a6332392012fa1a2e2e0be7211eca1efe2a2beb576a3c4629cbfc87270abd1a12d808c23077adfdadb5dde5814549407c4e89f181873df087bb2ed11a0bff47ea83b7c944d8b00180dbc56f038bf8e41
#TRUST-RSA-SHA256 50e784b513f7654a3672f953fcaea1e2259bf7ced2312740270d8bd81168e4ba5b39a6c09ab0640c1c35887bf1df1ad815f67dc1d8f9545063e7c3ebf69bd7ab46aa81f09b2c52ebcb783b45c93fe64e39ac4c15e0df3e9e289064c7f35e485a3673116cf2ce5ccf673cb3376438961cf179f0b5210dffa64ea36312c1b6c60dfab6baf173f2cb711d86e5dff8d54d023881e76487e9a2be3e20bb32c7e4bb19d72177de6f928fee4487d05686f14767e9e61aedea72401a0deeef7040ce905a43d7766f6b58e977af79731af6eebfc921800f83bab3cc4e0fb6127e3fc7b8ad6542d13cb817538823c2583d1b86604393d40c37d472b13ea58df4fd192a6795e166b4b3724219a67d0c4bbb68b02a5b6d0f4fb1ab85a3073c1b53a02e8731dcfef7a9fe7597e989718102861942a810d3dc27df3e90b5fd0fd72e95831fa1cb09597a0db8e4811f1c544019ecb9f0106ca6d2b6f98a33ff249440119705fdf58c2c554597e2f4797a06bfe45b4c7ae34bb54de85b2775c4ae168366cbf44e880b73298fa4fd3cfd955f4050a71b53a4ce238d8c762b792c7d5799166dc2ed8faf96550045362ef151b2f20503b855cdfb45c4374a3d36a89f85c4be647796776ad8d6badd446d4e664b0d22ddef008f1321e56f42bae4766b564c6c46dfc5b3938eaa19ec9be954558d5539a62f97b7b2d2dea0ddaaaa7a4722b70e2b64bd9c
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91572);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/11");

  script_cve_id("CVE-2016-2107");
  script_bugtraq_id(89760);
  script_xref(name:"EDB-ID", value:"39768");

  script_name(english:"OpenSSL AES-NI Padding Oracle MitM Information Disclosure");
  script_summary(english:"Checks if the server sends a RECORD_OVERFLOW alert to a crafted TLS handshake.");

  script_set_attribute(attribute:"synopsis", value:
"It was possible to obtain sensitive information from the remote host
with TLS-enabled services.");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by a man-in-the-middle (MitM) information
disclosure vulnerability due to an error in the implementation of
ciphersuites that use AES in CBC mode with HMAC-SHA1 or HMAC-SHA256.
The implementation is specially written to use the AES acceleration
available in x86/amd64 processors (AES-NI). The error messages
returned by the server allow allow a man-in-the-middle attacker to
conduct a padding oracle attack, resulting in the ability to decrypt
network traffic.");
  script_set_attribute(attribute:"see_also", value:"https://blog.filippo.io/luckyminus20/");
  # https://web-in-security.blogspot.com/2016/05/curious-padding-oracle-in-openssl-cve.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7647e9f0");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20160503.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSL version 1.0.1t / 1.0.2h or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-2107");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/05/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2016-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssl_supported_versions.nasl");
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

##
# Split the key block into IVs, cipher keys, and MAC keys.
#
# @anonparam keyblk Key block derived from the master secret.
#
# @return TRUE for success, FALSE otherwise.
##
function tls_set_keys(cipher_desc, keyblk)
{
  local_var mac_size, iv_size, key_size, pos, tls, mac, encryption;

  # Determine the size of the key block's fields.
  mac = cipher_field(name:cipher_desc, field:"mac");
  if ('SHA1' >< mac)        mac_size = 20;
  else if ('SHA256' >< mac) mac_size = 32;
  else return FALSE;

  encryption = cipher_field(name:cipher_desc, field:"encrypt");
  if ('AES-CBC(128)' >< encryption)      { key_size = 16; iv_size = 16; }
  else if ('AES-CBC(256)' >< encryption) { key_size = 32; iv_size = 16; }
  else return FALSE;

  # Ensure the block is big enough.
  if (strlen(keyblk) < 2 * (mac_size + key_size + iv_size))
    return FALSE;

  # Extract the data from the key block.
  pos = 0;
  tls['enc_mac_key'] = substr(keyblk, pos, pos + mac_size - 1); pos += mac_size;
  tls['dec_mac_key'] = substr(keyblk, pos, pos + mac_size - 1); pos += mac_size;
  tls['enc_key']     = substr(keyblk, pos, pos + key_size - 1); pos += key_size;
  tls['dec_key']     = substr(keyblk, pos, pos + key_size - 1); pos += key_size;
  tls['enc_iv']      = substr(keyblk, pos, pos + iv_size  - 1); pos += iv_size;
  tls['dec_iv']      = substr(keyblk, pos, pos + iv_size  - 1);

  return tls;
}

##
##
# Tries to make a TLS connection to the server.
#
# @return TRUE for success, FALSE otherwise.
##
function attack(port, ciphers)
{
  local_var soc, data, rec, srv_random, clt_random, version, cipher_desc;
  local_var cert, clt_cert_requested, skex, premaster, n, e, dh_privkey;
  local_var ckex, keyblk, tls_keys, tls_ciphertext, pubkey;

  # Get a socket to perform a handshake.
  soc = open_sock_ssl(port);
  if (!soc)
    # XXX-ALW Fix this error message
    return [FALSE, "open_sock_ssl", "Couldn't begin SSL handshake"];

  data = client_hello(
    v2hello:FALSE,
    version:mkword(TLS_10), # Record-layer version (RFC5246 Appendix E)
    maxver:mkword(TLS_12),  # Handshake version; maximum we support
    cipherspec:ciphers,
    extensions:tls_ext_ec(keys(curve_nid.tls))
  );
  send(socket:soc, data:data);
  rec = ssl_parse(blob:data);
  # Hang onto the Client Random; we need it to derive keys later.
  clt_random = mkdword(rec['time']) + rec['random'];

  # Read records one at a time. Expect to see at a minimum:
  # ServerHello, Certificate, and ServerHelloDone.
  while (TRUE)
  {
    # Receive a record from the server.
    data = recv_ssl(socket:soc);
    if (isnull(data))
    {
      close(soc);
      return [FALSE, "recv_ssl", "Did not receive expected ServerHello, ServerCertificate, etc."];
    }

    # ServerHello: Extract the random data for computation of keys.
    rec = ssl_find(
      blob:data,
      'content_type', SSL3_CONTENT_TYPE_HANDSHAKE,
      'handshake_type', SSL3_HANDSHAKE_TYPE_SERVER_HELLO
    );

    if (!isnull(rec))
    {
      # If server asks for version less than TLS 1.0 or higher than TLS 1.2, fail.
      if (rec['handshake_version'] < TLS_10 || rec['handshake_version'] > TLS_12)
        return [FALSE, "handshake_version", "Server does not support TLS 1.0, 1.1, or 1.2"];

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

  # Will contain an empty ClientCertificate (if requested), ClientKeyExchange,
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
  var cipher_kex = cipher_field(name:cipher_desc, field:"kex");
  if (cipher_kex =~ "RSA($|\()")
  {
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

    premaster = mkword(TLS_12) + rand_str(length:46);

    # Encrypt the premaster secret with server's RSA public key.
    ckex = rsa_public_encrypt(data:premaster, n:n, e:e);

    # It looks like TLS 1.0 and up prepend a two-byte length, but the
    # RFC is vague.
    if (version >= TLS_10)
      ckex = ssl_vldata_put(data:ckex, len:2);
  }
  else if (cipher_kex =~ "ECDH($|\()" && ecc_functions_available())
  {
    if (isnull(skex))
    {
      close(soc);
      return [FALSE, "ecdh_kx", "Server selected ECDHE key exchange but didn't provide a ServerKeyExchange"];
    }

    # Generate the client private key
    dh_privkey = rand_str(length:16);

    # Compute the premaster secret
    premaster = ecc_scalar_multiply(
      curve_nid:curve_nid.tls[skex['named_curve']],
      scalar:dh_privkey,
      x:substr(skex['pubkey'], 1, (strlen(skex['pubkey'])) / 2),
      y:substr(skex['pubkey'], (strlen(skex['pubkey']) / 2) + 1)
    );
    # Just the X coordinate of the curve point is used
    premaster = ecc_fe2osp(element:premaster.x, curve_nid:curve_nid.tls[skex['named_curve']]);

    pubkey = ecc_scalar_multiply(
      curve_nid:curve_nid.tls[skex['named_curve']],
      scalar:dh_privkey
    );

    pubkey.x = ecc_fe2osp(element:pubkey.x, curve_nid:curve_nid.tls[skex['named_curve']]);
    pubkey.y = ecc_fe2osp(element:pubkey.y, curve_nid:curve_nid.tls[skex['named_curve']]);

    ckex = ssl_vldata_put(
      # Uncompressed curve point encoding
      data:'\x04' + pubkey.x + pubkey.y,
      len:1
    );
  }
  else if (cipher_kex =~ "DH($|\()")
  {
    if (isnull(skex))
    {
      close(soc);
      return [FALSE, "dh_kx", "Server selected DH key exchange but didn't provide a ServerKeyExchange"];
    }

    # Generate the client private key,
    dh_privkey = rand_str(length:16);

    # Compute the premaster secret.
    premaster = bn_mod_exp(skex['dh_y'], dh_privkey, skex['dh_p']);

    # Encode the client's DH public key
    ckex = ssl_vldata_put(
      data:bn_mod_exp(skex['dh_g'], dh_privkey, skex['dh_p']),
      len:2
    );
  }
  else
  {
    close(soc);
    return [FALSE, "kx", "Unsupported key exchange method"];
  }

  # Create a ClientKeyExchange record
  data += ssl_mk_record(
    type:SSL3_CONTENT_TYPE_HANDSHAKE,
    version:version,
    data:ssl_mk_handshake_msg(
      type:SSL3_HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE,
      data:ckex
    )
  );

  tls_keys = tls_set_keys(
    cipher_desc:cipher_desc,
    keyblk:ssl_derive_keyblk(
      c_random:clt_random,
      s_random:srv_random,
      version:version,
      cipher_desc:cipher_desc,
      master:ssl_calc_master(
        c_random:clt_random,
        s_random:srv_random,
        version:version,
        premaster:premaster,
        cipher_desc:cipher_desc
      )
    )
  );

  if (tls_keys == FALSE)
  {
    close(soc);
    return [FALSE, "kx", "Failed to make TLS keys from key exchange"];
  }

  data += tls_mk_record(
    type:SSL3_CONTENT_TYPE_CHANGECIPHERSPEC,
    data:mkbyte(1),
    version:version
  );

  # Use a random IV, as it's included explicitly in TLS 1.1
  if (version >= TLS_11)
    tls_keys['enc_iv'] = rand_str(length:strlen(tls_keys['enc_iv']));

  # Finished message.
  # We make a record of just bad padding to trigger a RECORD_OVERFLOW alert.
  # 48 bytes of padding because:
  # o Must be a multiple of AES block size (16 bytes).
  # o Must be at least one byte bigger than the MAC size.
  # o SHA1 is 20 bytes, SHA256 is 32 bytes, so we round up to 48.
  # o SHA384 ciphersuites are not vulnerable.
  tls_ciphertext = aes_cbc_encrypt(
    data:crap(data:'\xff', length:48),
    iv:tls_keys['enc_iv'],
    key:tls_keys['enc_key']
  );
  # aes_cbc_encrypt() returns an array, [0] is ciphertext, [1] is CBC
  # residue (for TLS 1.0 IV). We don't retain the residue because we
  # don't intent to send any more records.
  tls_ciphertext = tls_ciphertext[0];

  # TLS 1.1 explicitly includes the IV in each record
  if (version >= TLS_11)
    tls_ciphertext = tls_keys['enc_iv'] + tls_ciphertext;

  data += tls_mk_record(
    type:SSL3_CONTENT_TYPE_HANDSHAKE,
    data:tls_ciphertext,
    version:version
  );

  # Send the ChangeCipherSpec and tampered Finished message
  send(socket:soc, data:data);

  while (TRUE)
  {
    # Receive a record from the server.
    data = recv_ssl(socket:soc);
    if (isnull(data))
    {
      close(soc);
      return [FALSE, "post_attack", "Server did not send an alert when sent a crafted Finished message"];
    }

    # Is it an alert?
    rec = ssl_find(
      blob:data,
      encrypted:FALSE,
      'content_type', SSL3_CONTENT_TYPE_ALERT
    );

    if (!isnull(rec))
    {
      close(soc);
      if (rec['level'] == 2 && rec['description'] == SSL3_ALERT_TYPE_RECORD_OVERFLOW)
        return [TRUE, "post_attack", "Server sent RECORD_OVERFLOW alert"];
      else
        return [FALSE, "post_attack", "Server sent alert to tampered Finished. Level: " + rec['level'] + ", description: " + rec['description']];
    }
  }
}

get_kb_item_or_exit('SSL/Supported');

# Get a port that uses SSL.
port = get_ssl_ports(fork:TRUE);

if (isnull(port))
  exit(1, 'The host does not appear to have any SSL-based services.');

# Find out if the port is open.
if (!get_port_state(port))
  audit(AUDIT_PORT_CLOSED, port, "TCP");

# Ciphersuites should basically be the "Cartesian product" of:
# * DHE and RSA key exchanges
# * AES-CBC with 128- and 256-bit keys
# * SHA1 and SHA256 HMACs (SHA384 ciphersuites are not vulnerable)
# TODO: should support ECDHE and ECDSA, once we can do that from NASL.

# We test SHA1 separately from SHA256 and check if *either* was
# vulnerable, because vulnerable 1.0.1 servers support SHA256 but are
# only vulnerable on SHA1 ciphersuites. If we offered SHA1 and SHA256
# at the same time and the server preferred SHA256, it'd be a false
# negative.

cipher_list_sha1 =
  ciphers['TLS1_CK_RSA_WITH_AES_128_CBC_SHA'] + # <- Required by all TLS 1.2 impls.
  ciphers['TLS1_CK_RSA_WITH_AES_256_CBC_SHA'] +
  ciphers['TLS1_CK_DHE_RSA_WITH_AES_128_CBC_SHA'] +
  ciphers['TLS1_CK_DHE_RSA_WITH_AES_256_CBC_SHA'];

cipher_list_sha256 =
    ciphers['TLS1_RSA_WITH_AES_128_CBC_SHA256'] +
    ciphers['TLS1_RSA_WITH_AES_256_CBC_SHA256'] +
    ciphers['TLS1_DHE_RSA_WITH_AES_128_CBC_SHA256'] +
    ciphers['TLS1_DHE_RSA_WITH_AES_256_CBC_SHA256'];

if (ecc_functions_available())
{
  cipher_list_sha1 +=
    ciphers["TLS1_CK_ECDHE_RSA_WITH_AES_128_CBC_SHA"] +
    ciphers["TLS1_CK_ECDHE_RSA_WITH_AES_256_CBC_SHA"];

  cipher_list_sha256 +=
    ciphers["TLS1_ECDHE_RSA_WITH_AES_128_CBC_SHA256"] +
    ciphers["TLS1_ECDHE_RSA_WITH_AES_256_CBC_SHA256"];
}

sha1_result = attack(port:port, ciphers:cipher_list_sha1);

# Only do SHA256 test if we didn't find a vuln with SHA1.
if (sha1_result[0] == FALSE)
  sha256_result = attack(port:port, ciphers:cipher_list_sha256);

if (sha1_result[0] == TRUE || sha256_result[0] == TRUE)
{
  security_report_v4(
    port:port,
    severity:SECURITY_NOTE,
    extra:
      'Nessus was able to trigger a RECORD_OVERFLOW alert in the\n' +
      'remote service by sending a crafted SSL "Finished" message.'
  );
}
else
{
  exit(0,
    "[Port " + port + "] " +
    "SHA1 test: " + sha1_result[1] + ": " + sha1_result[2] + ". " +
    "SHA256 test: " + sha256_result[1] + ": " + sha256_result[2]);
}

