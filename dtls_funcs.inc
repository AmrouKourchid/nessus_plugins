#TRUSTED 354d1d9a9c079a4285fa25e994e8cf7e451e340fec2696a27da8fb7b22127a4ce8913d470a5d776ca24d0afe521d3e5138c985ed91444b15502295f72726a772c7a41acee080f0590f581c4381729cedfd598582f373e6ef3975d71eef66e71dc9cd641d042480aa7f276319ea82e572c3bf374cfc2dd8273b3c50afe36c7ee18cc9422b97f9b17b3d0136f9fefaf78c14f8e272e1650458feae9b2dac50697d6180919b2f9573bb31d478972a533ed853fd3c7350a61a0e646aeeb8c47e4841ec5bfb6b6cfe04c32a94abbfb288736f75ea6e6f2e44578a0e175b29c3e3674005d47f188ec9f6b895ed8f24c55a47e5806a43bce555af947ed7c04723f7cbff802cc375d633a688ce876107f8f36707dba7a0fd8e081f1aa3b6866cde28de9278d343812b4ea269255853b0b67ae5fcb5a2d40371123045324847c7ed8eee56242c010ce7f0f149297f374b31f475d466dc6b3c1185313227fdaff390b14d0ec4235e7e774fe9a68d3fd08371fe6f57aaccafce30aeb88c30508249b4fb0909e2bd18f0b6666dbc00f9d3b67070d7e23d19c6661e14202f4ba3334aa53fc0763b54fea30519962746c657a98ebf9321666d498d6f78ddb4cd2c42908c5e11fc9272f2eee52ab03b437729a58649a903d8f57b5f2a3e8ef97f3c611df61896dfd7872b95b5d917480332224683cfbcb5858b5abc6f4e353350b770f664833830
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# Revision 1.1
#
include("compat_shared.inc");
include("byte_func.inc");
include("debug.inc");
include("ecc.inc");
include("x509_func.inc");
include("ssl_funcs.inc");

global_var _dtls = {};

#A selection of cipher suites to try
global_var dtls10_ciphers = raw_string(
   ciphers["TLS12_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"] +
   ciphers["TLS12_ECDHE_RSA_WITH_AES_256_GCM_SHA384"] +
   ciphers["TLS12_DHE_RSA_WITH_AES_256_GCM_SHA384"] +
   ciphers["TLS12_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"] +
   ciphers["TLS12_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"] +
   ciphers["TLS12_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256"] +
   ciphers["TLS12_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"] +
   ciphers["TLS12_ECDHE_RSA_WITH_AES_128_GCM_SHA256"] +
   ciphers["TLS12_DHE_RSA_WITH_AES_128_GCM_SHA256"] +
   ciphers["TLS1_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384"] +
   ciphers["TLS1_ECDHE_RSA_WITH_AES_256_CBC_SHA384"] +
   ciphers["TLS1_DHE_RSA_WITH_AES_256_CBC_SHA256"] +
   ciphers["TLS1_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"] +
   ciphers["TLS1_ECDHE_RSA_WITH_AES_128_CBC_SHA256"] +
   ciphers["TLS1_DHE_RSA_WITH_AES_128_CBC_SHA256"] +
   ciphers["TLS1_CK_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"] +
   ciphers["TLS1_CK_ECDHE_RSA_WITH_AES_256_CBC_SHA"] +
   ciphers["TLS1_CK_DHE_RSA_WITH_AES_256_CBC_SHA"] +
   ciphers["TLS1_CK_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"] +
   ciphers["TLS1_CK_ECDHE_RSA_WITH_AES_128_CBC_SHA"] +
   ciphers["TLS1_CK_DHE_RSA_WITH_AES_128_CBC_SHA"] +
   ciphers["TLS12_RSA_WITH_AES_256_GCM_SHA384"] +
   ciphers["TLS12_RSA_WITH_AES_128_GCM_SHA256"] +
   ciphers["TLS1_RSA_WITH_AES_256_CBC_SHA256"] +
   ciphers["TLS1_RSA_WITH_AES_128_CBC_SHA256"] +
   ciphers["TLS1_CK_RSA_WITH_AES_256_CBC_SHA"] +
   ciphers["TLS1_CK_RSA_WITH_AES_128_CBC_SHA"]
);

global_var dtls12_ciphers = raw_string(
  ciphers["TLS12_ECDHE_RSA_WITH_AES_256_GCM_SHA384"] +
  ciphers["TLS12_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"] +
  ciphers["TLS1_ECDHE_RSA_WITH_AES_256_CBC_SHA384"] +
  ciphers["TLS1_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384"] +
  ciphers["TLS1_CK_ECDHE_RSA_WITH_AES_256_CBC_SHA"] +
  ciphers["TLS1_CK_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"] +
  ciphers["TLS12_DH_DSS_WITH_AES_256_GCM_SHA384"] +
  ciphers["TLS12_DHE_DSS_WITH_AES_256_GCM_SHA384"] +
  ciphers["TLS12_DH_RSA_WITH_AES_256_GCM_SHA384"] +
  ciphers["TLS12_DHE_RSA_WITH_AES_256_GCM_SHA384"] +
  ciphers["TLS1_DHE_RSA_WITH_AES_256_CBC_SHA256"] +
  ciphers["TLS1_DHE_DSS_WITH_AES_256_CBC_SHA256"] +
  ciphers["TLS1_DH_RSA_WITH_AES_256_CBC_SHA256"] +
  ciphers["TLS1_DH_DSS_WITH_AES_256_CBC_SHA256"] +
  ciphers["TLS1_CK_DHE_RSA_WITH_AES_256_CBC_SHA"] +
  ciphers["TLS1_CK_DHE_DSS_WITH_AES_256_CBC_SHA"] +
  ciphers["TLS1_CK_DH_RSA_WITH_AES_256_CBC_SHA"] +
  ciphers["TLS1_CK_DH_DSS_WITH_AES_256_CBC_SHA"] +
  ciphers["TLS1_CK_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA"] +
  ciphers["TLS1_CK_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA"] +
  ciphers["TLS1_CK_DH_RSA_WITH_CAMELLIA_256_CBC_SHA"] +
  ciphers["TLS1_CK_DH_DSS_WITH_CAMELLIA_256_CBC_SHA"] +
  ciphers["TLS12_ECDH_RSA_WITH_AES_256_GCM_SHA384"] +
  ciphers["TLS12_ECDH_ECDSA_WITH_AES_256_GCM_SHA384"] +
  ciphers["TLS1_ECDH_RSA_WITH_AES_256_CBC_SHA384"] +
  ciphers["TLS1_ECDH_ECDSA_WITH_AES_256_CBC_SHA384"] +
  ciphers["TLS1_CK_ECDH_RSA_WITH_AES_256_CBC_SHA"] +
  ciphers["TLS1_CK_ECDH_ECDSA_WITH_AES_256_CBC_SHA"] +
  ciphers["TLS12_RSA_WITH_AES_256_GCM_SHA384"] +
  ciphers["TLS1_RSA_WITH_AES_256_CBC_SHA256"] +
  ciphers["TLS1_CK_RSA_WITH_AES_256_CBC_SHA"] +
  ciphers["TLS1_CK_RSA_WITH_CAMELLIA_256_CBC_SHA"] +
  ciphers["TLS12_ECDHE_RSA_WITH_AES_128_GCM_SHA256"] +
  ciphers["TLS12_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"] +
  ciphers["TLS1_ECDHE_RSA_WITH_AES_128_CBC_SHA256"] +
  ciphers["TLS1_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"] +
  ciphers["TLS1_CK_ECDHE_RSA_WITH_AES_128_CBC_SHA"] +
  ciphers["TLS1_CK_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"] +
  ciphers["TLS12_DH_DSS_WITH_AES_128_GCM_SHA256"] +
  ciphers["TLS12_DHE_DSS_WITH_AES_128_GCM_SHA256"] +
  ciphers["TLS12_DH_RSA_WITH_AES_128_GCM_SHA256"] +
  ciphers["TLS12_DHE_RSA_WITH_AES_128_GCM_SHA256"] +
  ciphers["TLS1_DHE_RSA_WITH_AES_128_CBC_SHA256"] +
  ciphers["TLS1_DHE_DSS_WITH_AES_128_CBC_SHA256"] +
  ciphers["TLS1_DH_RSA_WITH_AES_128_CBC_SHA256"] +
  ciphers["TLS1_DH_DSS_WITH_AES_128_CBC_SHA256"] +
  ciphers["TLS1_CK_DHE_RSA_WITH_AES_128_CBC_SHA"] +
  ciphers["TLS1_CK_DHE_DSS_WITH_AES_128_CBC_SHA"] +
  ciphers["TLS1_CK_DH_RSA_WITH_AES_128_CBC_SHA"] +
  ciphers["TLS1_CK_DH_DSS_WITH_AES_128_CBC_SHA"] +
  ciphers["TLS1_CK_DHE_RSA_WITH_SEED_CBC_SHA"] +
  ciphers["TLS1_CK_DHE_DSS_WITH_SEED_CBC_SHA"] +
  ciphers["TLS1_CK_DH_RSA_WITH_SEED_CBC_SHA"] +
  ciphers["TLS1_CK_DH_DSS_WITH_SEED_CBC_SHA"] +
  ciphers["TLS1_CK_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA"] +
  ciphers["TLS1_CK_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA"] +
  ciphers["TLS1_CK_DH_RSA_WITH_CAMELLIA_128_CBC_SHA"] +
  ciphers["TLS1_CK_DH_DSS_WITH_CAMELLIA_128_CBC_SHA"] +
  ciphers["TLS12_ECDH_RSA_WITH_AES_128_GCM_SHA256"] +
  ciphers["TLS12_ECDH_ECDSA_WITH_AES_128_GCM_SHA256"] +
  ciphers["TLS1_ECDH_RSA_WITH_AES_128_CBC_SHA256"] +
  ciphers["TLS1_ECDH_ECDSA_WITH_AES_128_CBC_SHA256"] +
  ciphers["TLS1_CK_ECDH_RSA_WITH_AES_128_CBC_SHA"] +
  ciphers["TLS1_CK_ECDH_ECDSA_WITH_AES_128_CBC_SHA"] +
  ciphers["TLS12_RSA_WITH_AES_128_GCM_SHA256"] +
  ciphers["TLS1_RSA_WITH_AES_128_CBC_SHA256"] +
  ciphers["TLS1_CK_RSA_WITH_AES_128_CBC_SHA"] +
  ciphers["TLS1_CK_RSA_WITH_SEED_CBC_SHA"] +
  ciphers["TLS1_CK_RSA_WITH_CAMELLIA_128_CBC_SHA"] +
  ciphers["TLS1_CK_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"] +
  ciphers["TLS1_CK_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA"] +
  ciphers["TLS1_CK_DHE_RSA_WITH_3DES_EDE_CBC_SHA"] +
  ciphers["TLS1_CK_DHE_DSS_WITH_3DES_EDE_CBC_SHA"] +
  ciphers["TLS1_CK_DH_RSA_WITH_3DES_EDE_CBC_SHA"] +
  ciphers["TLS1_CK_DH_DSS_WITH_3DES_EDE_CBC_SHA"] +
  ciphers["TLS1_CK_ECDH_RSA_WITH_3DES_EDE_CBC_SHA"] +
  ciphers["TLS1_CK_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA"] +
  ciphers["TLS1_CK_RSA_WITH_3DES_EDE_CBC_SHA"] +
  ciphers["TLS1_CK_RSA_WITH_IDEA_CBC_SHA"]
);

# Object dtls
#  DTLS state for one connection
#
##
object dtls
{
  var soc;                     # UDP socket
  var port;
  var errors;
  var buf;                     # A buffer to accumulate responses
  var epoch;                   # Cipher change epoch - part of the sequence no.
  var version;                 # DTLS version
  var tls_version;             # TLS version corresponding to the DTLS version
  var cipher;                  # The negotiated cipher code.
  var cipher_desc;             # Tenable description of the negotiated cipher.
  var rseq;                    # Message sequence within current epoch
  var exts;                    # TLS extensions
  var compmeths;               # Compression methods extension
  var timeout;                 # Read/write timeout
  var init;                    # Boolean indicating that this instance is initialized.
  var enc_mac_key;             # Key for calculating the encryption MAC
  var dec_mac_key;             # Key for calculating the decryption MAC
  var enc_key;                 # Symmetric key for client encryption
  var dec_key;                 # Symmetric key for client decryption
  var enc_iv;                  # Client encryption initialization vector
  var dec_iv;                  # Client decryption initialization vector
  var tag_len;                 # Length of computed tag for AEAD ciphers
  var key_size;                # Length of the cipher keys
  var mode;                    # Encryption scheme mode
  var cipher_block_size;       # Block size
  var client_hello;            # Most recent ClientHello
  var testing;                 # A flag indicating this is running in testing mode.
  var test_send_buf;           # A buffer to collect sent messages during testing mode.

  # How long we want to wait for the last message of a given flight.
  var FLIGHT_TIMEOUT = 20;

  ##
  # Constructs a dtls object instance.
  #
  # @anonparam <first>  An open UDP socket description.
  # @anonparam <second> A DTLS port on the target server.
  ##
  function dtls()
  {
    this.soc = _FCT_ANON_ARGS[0];
    this.port = _FCT_ANON_ARGS[1];
    this.epoch = 0;
    this.rseq = 0;
    this.buf = '';
    this.init = FALSE;
    this.testing = FALSE;

    if(get_kb_item("TEST_dtls_in_flatline"))
      this.testing = TRUE;
  }

  ##
  # Cleans up a dtls object instance before destruction.
  ##
  function ~dtls()
  {
    if(this.soc && !this.testing)
      close(this.soc);
  }

  ##
  # Set the DTLS and corresponding TLS protocol versions.
  #
  # @anonparam <first> Integer DTLS protocol version (0xfeff or 0xfefd)
  ##
  public function set_version()
  {
    this.version = _FCT_ANON_ARGS[0];
    this.tls_version = convert_dtls_ver_to_tls_ver(dtlsver:version);
  }

  ##
  # Set the message accumulation buffer.
  #
  # @anonparam <first> String message.
  ##
  public function set_buf()
  {
    this.buf = _FCT_ANON_ARGS[0];
  }

  ##
  # Initialize the DTLS structure.
  #
  # @param version The DTLS version ID.
  # @param suites A list of cipher suite IDs to support.
  # @param exts DTLS extensions to send in ClientHello.
  # @param compmeths Compression methods to send in ClientHello.
  # @param securerenegotiation TRUE if we advertise support for secure renegotiation.
  # @param timeout Socket recv timeout.
  #
  # @return TRUE if nothing went wrong, or NULL on error.
  ##
  public function init(version, suites, exts, compmeths, securerenegotiation, timeout)
  {
    local_var c, i, supported;

    if(!this.testing && (!this.soc || !socket_ready(this.soc)))
      return this.set_error('dtls_init(): Socket on port ' + this.port + ' is not ready.');

    # DTLS uses big endian format
    set_byte_order(BYTE_ORDER_BIG_ENDIAN);

    # Check cipher suites
    if(isnull(suites))
      return this.set_error('dtls_init(): no cipher suites specified.');

    if(strlen(suites) % 2)
      return this.set_error('dtls_init(): invalid cipher suites specified.');

    # TLS_EMPTY_RENEGOTIATION_INFO_SCSV  - https://tools.ietf.org/html/rfc5746
    if(securerenegotiation)
      suites += raw_string(0x00, 0xFF);

    # Initially set to a list of cipher suites supported by the client.
    # When ServerHello is received, it's set to the agreed suite.
    this.set_cipher(suites);
    this.set_cipher_desc(NULL);

    # Set DTLS extensions
    this.exts = exts;

    # Set compression methods
    this.compmeths = compmeths;

    # Socket recv() timeout
    if(isnull(timeout))
      timeout = 5;

    if(!isnull(this.errors))
    {
      this.errors = NULL;
      dbg::log(src: FUNCTION_NAME, msg: "Resetting errors for new connection on port " + this.port + ".");
    }

    this.timeout = timeout;
    this.init = TRUE;

    return TRUE;
  }

  ##
  # Connect to a remote DTLS service.
  #
  # @return TRUE on success, NULL on error.
  ##
  public function connect()
  {
    local_var rec, hfrags, clt_random;

    if(!this.init)
    {
      dbg::log(src: FUNCTION_NAME, msg: "Connection is not initialized.");
      return NULL;
    }

    hfrags = [];

    clt_random = dec2hex(num:unixtime()) + rand_str(length:28);

    rec = this.do_client_hello(hfrags:hfrags, clt_random:clt_random);
    if(!rec)
      return this.set_error('Failed to complete a DTLS hello handshake sequence.');

    return this.complete_handshake(rec:rec,
                                   hfrags:hfrags,
                                   clt_random:clt_random,
                                   timeout:this.timeout);
  }

  ##
  # Connect to a remote DTLS service.
  #
  # @param hfrags     Reference parameter used to pass back assembled server hello messages.
  # @param clt_random Client's random secret.
  #
  # @return Returns a DTLS record assembled from fragments returned by the server, NULL on error.
  ##
  public function do_client_hello(&hfrags, clt_random)
  {
    local_var ctype, hellodone, i, rec;
    local_var cookie, ret, msg_hello1, msg_hello2;
    local_var t1;

    # Handshake message sequence number.
    this.reset_rseq();

    msg_hello1 = this.client_hello(
      version     : this.version,
      challenge   : clt_random,
      cipherspec  : this.cipher,
      mseq        : this.rseq,
      exts        : this.exts,
      compmeths   : this.compmeths
    );

    #
    # Wait for HelloVerifyRequest, retransmit ClientHello if needed.
    #
    t1 = unixtime();
    if(! this.send_msg(type:SSL3_CONTENT_TYPE_HANDSHAKE, data:msg_hello1))
      return this.set_error('Failed to send the first ClientHello.');

    rec = this.recv_rec();
    if(!rec || ord(rec[13]) != SSL3_HANDSHAKE_TYPE_HELLO_VERIFY_REQUEST)
      return this.set_error('Failed to receive a DTLS HelloVerifyRequest handshake message.');

    # Extract the cookie from HelloVerifyRequest.
    ret = ssl_parse(blob:rec);
    cookie = ret["cookie"];
    if(isnull(cookie))
      return this.set_error('Failed to get the HelloVerifyRequest cookie.');

    # Create the second ClientHello with cookie
    msg_hello2 = this.client_hello(
      version     : this.version,
      challenge   : clt_random,
      cipherspec  : this.cipher,
      mseq        : this.rseq,
      cookie      : cookie,
      exts        : this.exts,
      compmeths   : this.compmeths);

    this.client_hello = msg_hello2;

    # Storage to hold received handshake messages.
    #  - A record can contain multiple handshake messages.
    #  - A handshake message can span multiple records.
    hfrags = [];

    #
    # Wait for ServerHelloDone, retransmit ClientHello (with cookie) if needed.
    #
    hellodone = FALSE;
    t1 = unixtime();
    while (unixtime() - t1 < FLIGHT_TIMEOUT)
    {
      # Send the ClientHello with cookie in it.
      if(! this.send_msg(type:SSL3_CONTENT_TYPE_HANDSHAKE, data:msg_hello2))
        return this.set_error('Failed to send the second ClientHello.');

      # Expect ServerHello, Certificate, [ServerKeyExchange], [CertificateRequest], ServerHelloDone.
      i = 0;
      while (TRUE)
      {
        # Receive a record from the server.
        rec = this.recv_rec();
        if (isnull(rec)) break;

        ctype = ord(rec[0]);
        # Alert
        if(ctype == SSL3_CONTENT_TYPE_ALERT)
          return this.set_error('Received an alert message.');
        # Handshake
        else if (ctype == SSL3_CONTENT_TYPE_HANDSHAKE)
        {
          # Accumulate handshake frags from the record.
          if(! this.accumulate_hs_frags(rec:rec, hfrags:hfrags, hellodone:hellodone))
            return this.set_error('Failed to accumulate handshake fragment(s) from a DTLS record.');

          # Exit read loop if ServerHelloDone is received or
          # too many handshake msgs received without seeing a ServerHelloDone.
          if(hellodone || i++ > 32) break;
        }
        else
        {
          return this.set_error('Received a record of unexpected content type ' + ctype + '.');
        }
      }

      if(hellodone) break;
    }

    # Make sure we got ServerHelloDone
    if(! hellodone)
      return this.set_error('ServerHelloDone not received.');

    # Assemble handshake fragments
    return this.assemble_hs_frags(hfrags:hfrags, rec:rec);
  }

  ##
  # Send an alert message to the target
  #
  # @param alert_msg   The one byte SSLv3 alert code.  Example: SSL3_ALERT_TYPE_HANDSHAKE_FAILURE
  # @param alert_level The one byte SSLv3 alert level. Example: SSL3_ALERT_TYPE_FATAL
  #
  # Returns TRUE if the alert was sent successfully, NULL otherwise.
  ##
  public function send_alert(alert_msg, alert_level)
  {
    local_var rec, data;

    if(isnull(alert_level) || isnull(alert_msg))
      return this.set_error('Sending alert failed.  Arguments missing.');

    data = mkbyte(alert_level) + mkbyte(alert_msg);
    return this.send_msg(type:SSL3_CONTENT_TYPE_ALERT, data:data);
  }

  ##
  # Connect to a remote DTLS service.
  #
  # @param suites     A list of cipher suite IDs to support.
  # @param exts       DTLS extensions to send in ClientHello.
  # @param clt_random Client's random secret.
  # @param timeout    Socket recv timeout.
  #
  # @return TRUE on success, NULL on error.
  # @remark This function will not attempt protocol negotiation.  If the server
  #         responds to the handshake with a version different from the one
  #         requested, the handshake will fail.
  ##
  public function complete_handshake(rec, hfrags, clt_random, timeout)
  {
    local_var cert, cipher_desc, ctype, msg;
    local_var ccs, clt_cert_req, ckex, e, i, n, skex;
    local_var keyblk, master, premaster, srv_random;
    local_var clt_finished, hs, srv_finished, ret;
    local_var dh_privkey, embedded_srv_finished, pubkey;
    local_var msg_cert, msg_clt_kex, msg_ccs, msg_fin;
    local_var t1, cipher_kex, mseq;

    msg = NULL;

    # Process ServerHello
    ret = ssl_find(
        blob:rec,
        'content_type', SSL3_CONTENT_TYPE_HANDSHAKE,
        'handshake_type', SSL3_HANDSHAKE_TYPE_SERVER_HELLO
    );

    if(isnull(ret['time']) || isnull(ret['random']))
      return this.set_error('Server random not found.');

    srv_random = mkdword(ret['time']) + ret['random'];

    if(ret['version'] != this.version)
    {
      send_alert(alert_msg: SSL3_ALERT_TYPE_PROTOCOL_VERSION, alert_level: SSL3_ALERT_TYPE_FATAL);
      return this.set_error('Server does not support the requested version.');
    }

    # Start collecting handshake messages, which are used
    # to generate the encrypted Finished message.
    #
    # The initial ClientHello and HelloVerifyRequest are not
    # included in the calculation of the verify_data for the
    # Finished message.
    hs = this.client_hello;

    # Add ServerHello for Finished calculation.
    hs += hfrags[SSL3_HANDSHAKE_TYPE_SERVER_HELLO];

    # Store the negotiated cipher suite.
    if(isnull(ret['cipher_spec']))
      return this.set_error('Failed to get the negotiated cipher suite.');

    # Make sure the negotiated cipher is in the list we requested.
    if (! this.cipher_in_list(mkword(ret['cipher_spec']), this.cipher))
      return this.set_error('Negotiated cipher suite is not in the requested list.');

    this.set_cipher(mkword(ret['cipher_spec']));

    cipher_desc = this.get_cipher_desc();
    if(isnull(cipher_desc))
        return this.set_error('Failed to get the description of the negotiated cipher suite.');

    # Process Certificate
    cert = NULL;
    ret = ssl_find(
        blob:rec,
        'content_type', SSL3_CONTENT_TYPE_HANDSHAKE,
        'handshake_type', SSL3_HANDSHAKE_TYPE_CERTIFICATE
    );
    if (!isnull(ret) && max_index(ret['certificates']) > 0)
    {
      # First cert in the chain should be the server cert.
      cert = parse_der_cert(cert:ret['certificates'][0]);
      cert = cert['tbsCertificate'];
    }
    if (isnull(cert))
      return this.set_error('Failed to get server certificate.');

    # Add server Certificate for Finished calculation.
    hs += hfrags[SSL3_HANDSHAKE_TYPE_CERTIFICATE];

    # Process ServerKeyExchange if any.
    msg = hfrags[SSL3_HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE];
    if(msg)
    {
      ret = ssl_find(
          blob:rec,
          'content_type', SSL3_CONTENT_TYPE_HANDSHAKE,
          'handshake_type', SSL3_HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE
      );
      skex = ssl_parse_srv_kex(blob:ret['data'], cipher:cipher_desc, version:this.tls_version);
      if(isnull(skex))
        return this.set_error('Failed to parse ServerKeyExchange.');

      # Add ServerKeyExchange for Finished calculation.
      hs += msg;
    }

    # Negotiated cipher suite uses RSA for key exchange.
    cipher_kex = cipher_field(name:cipher_desc, field:"kex");
    if (cipher_kex =~ "RSA(\(|$)")
    {
      # Calculate master secret
      if (isnull(cert['subjectPublicKeyInfo']) || isnull(cert['subjectPublicKeyInfo'][1]))
        return this.set_error('Failed to get subjectPublicKeyInfo in ServerCertificate');

      n = cert['subjectPublicKeyInfo'][1][0];
      e = cert['subjectPublicKeyInfo'][1][1];
      if(isnull(n) || isnull(e))
        return this.set_error('Failed to extract public key from server certificate.');

      # Create the premaster secret.
      # version is the highest version offered in ClientHello
      premaster = mkword(this.version) + rand_str(length:46);

      # Encrypt the premaster secret with server's RSA public key.
      ckex = rsa_public_encrypt(data:premaster, n:n, e:e);
      if(isnull(ckex))
        return this.set_error('Failed to encrypt the premaster secret.');

      # Encode the client key exchange data.
      ckex = ssl_vldata_put(data:ckex, len:2);
    }
    # Negotiated cipher suite uses ECDH for key exchange.
    else if (cipher_kex =~ "ECDH(\(|$)")
    {
      if(skex['kex'] != 'ecdh' ||
        isnull(skex['curve_type']) ||
        isnull(skex['named_curve']) ||
        isnull(skex['pubkey'])
      ) return this.set_error('Failed to extract EC parameters in ServerKeyExchange.');

      var nid = curve_nid.tls[skex['named_curve']];

      if (isnull(nid))
        this.set_error('Unsupported EC named curve in ServerKeyExchange.');

      # Generate the client private key
      dh_privkey = ecc_generate_secret_key(curve_nid:nid);

      # Compute the premaster secret
      premaster = ecc_scalar_multiply(
        curve_nid:nid,
        scalar:dh_privkey,
        x:substr(skex['pubkey'], 1, (strlen(skex['pubkey'])) / 2),
        y:substr(skex['pubkey'], (strlen(skex['pubkey']) / 2) + 1)
      );
      # Just the X coordinate of the curve point is used
      premaster = ecc_fe2osp(element:premaster.x, curve_nid:nid);

      pubkey = ecc_scalar_multiply(
        curve_nid:nid,
        scalar:dh_privkey
      );

      pubkey.x = ecc_fe2osp(element:pubkey.x, curve_nid:nid);
      pubkey.y = ecc_fe2osp(element:pubkey.y, curve_nid:nid);

      ckex = ssl_vldata_put(
        # Uncompressed curve point encoding
        data:'\x04' + pubkey.x + pubkey.y,
        len:1
      );
    }
    # Negotiated cipher suite uses DH for key exchange.
    else if (cipher_kex =~ "DH(\(|$)")
    {
      if(skex['kex'] != 'dh' ||
        isnull(skex['dh_y']) ||
        isnull(skex['dh_p']) ||
        isnull(skex['dh_g'])
      ) return this.set_error('Failed to extract DH parameters in ServerKeyExchange.');

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
      return this.set_error('Unsupported key exchange method.');

    # Process CertificateRequest if any.
    msg = hfrags[SSL3_HANDSHAKE_TYPE_CERTIFICATE_REQUEST];
    if(msg)
    {
      ret = ssl_find(
          blob:rec,
          'content_type', SSL3_CONTENT_TYPE_HANDSHAKE,
          'handshake_type', SSL3_HANDSHAKE_TYPE_CERTIFICATE_REQUEST
      );
      if(isnull(ret))
        return this.set_error('Failed to parse CertificateRequest.');

      clt_cert_req = TRUE;

      # Add CertificateRequest for Finished calculation.
      hs += msg;
    }

    # Add ServerHelloDone for Finished calculation.
    hs += hfrags[SSL3_HANDSHAKE_TYPE_SERVER_HELLO_DONE];

    mseq = this.rseq;

    # Create an empty client cert if requested.
    if(clt_cert_req)
    {
      msg = ''; # no cert chain
      msg = ssl_vldata_put(data:msg, len:3); # cert chain
      msg_cert = this.mk_handshake_msg(
        type        : SSL3_HANDSHAKE_TYPE_CERTIFICATE,
        message_seq : mseq++,
        data        : msg
      );

      # Add ServerHelloDone for Finished calculation.
      hs += msg_cert;
    }

    # Create ClientKeyExchange
    msg_clt_kex = this.mk_handshake_msg(
      type        : SSL3_HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE,
      message_seq : mseq++,
      data        : ckex);

    # Added ClientKeyExchange for Finished calculation
    hs += msg_clt_kex;
    # Create ChangeCipherSpec message.
    msg_ccs = mkbyte(1);

    # Compute the keys.
    master = tls_calc_master(
      premaster   : premaster,
      c_random    : clt_random,
      s_random    : srv_random,
      version     : this.tls_version,
      cipher_desc : cipher_desc
    );

    if(isnull( master))
      return this.set_error('Failed to compute master secret.');

    keyblk = tls_derive_keyblk(
      master      : master,
      c_random    : clt_random,
      s_random    : srv_random,
      version     : this.tls_version,
      cipher_desc : cipher_desc
    );

    if(isnull(keyblk))
      return this.set_error('Failed to derive key block.');

    if (! this.set_keys(keyblk))
      return this.set_error('dtls::set_keys() failed.');

    # Compute the Finished value for the client.
    clt_finished = ssl_calc_finished(
      master:master,
      handshake:hs,
      is_client:TRUE,
      version:this.tls_version,
      cipher_desc:cipher_desc);

    msg_fin = this.mk_handshake_msg(
      type        : SSL3_HANDSHAKE_TYPE_FINISHED,
      message_seq : mseq++,
      data        : clt_finished);

    # Compute the Finished value for the server.
    #
    # The server has one more handshake message (the client's Finished)
    # to include when computing its Finished value.
    hs += msg_fin;
    srv_finished = ssl_calc_finished(
      master:master,
      handshake:hs,
      is_client:FALSE,
      version:this.tls_version,
      cipher_desc:cipher_desc);

    ccs = FALSE;

    #
    # Wait for server Finished, retransmit flight if needed.
    #
    t1 = unixtime();
    while (unixtime() - t1 < FLIGHT_TIMEOUT)
    {
      # Send empty client Certificate if requested.
      if(clt_cert_req)
      {
        if(! this.send_msg(type:SSL3_CONTENT_TYPE_HANDSHAKE, data:msg_cert))
          return this.set_error('Failed to send client Certificate.');
      }

      # Send ClientKeyExchange
      if(! this.send_msg(type:SSL3_CONTENT_TYPE_HANDSHAKE, data:msg_clt_kex))
        return this.set_error('Failed to send ClientKeyExchange.');

      # Send ChangeCipherSpec
      if(!this.send_msg(type:SSL3_CONTENT_TYPE_CHANGECIPHERSPEC, data:msg_ccs))
        return this.set_error('Failed to send ChangeCipherSpec.');

      # Send Finished
      if(! this.send_msg(type:SSL3_CONTENT_TYPE_HANDSHAKE, data:msg_fin))
        return this.set_error('Failed to send client Finished.');

      # Expect ChangeCipherSpec, Finished
      i = 0;
      while (TRUE)
      {
        # Receive a record from the server.
        rec = this.recv_rec();
        if (isnull(rec)) break;

        # Too many records.
        if(i++ > 16) break;

        ctype = ord(rec[0]);

        # ChangeCipherSpec
        if(ctype == SSL3_CONTENT_TYPE_CHANGECIPHERSPEC)
        {
          ccs = TRUE;
          continue;
        }
        # Alert
        else if(ctype == SSL3_CONTENT_TYPE_ALERT)
          return this.set_error('Alert received after sending a client Finished handshake message.');
        # Handshake
        else if (ctype == SSL3_CONTENT_TYPE_HANDSHAKE)
        {
          # Decrypt record if server ChangeCipherSpec is seen.
          if(ccs)
          {
            msg = this.decrypt_record(rec);
            if(isnull(msg))
              return this.set_error('Failed to decrypt a DTLS record.');

            rec = this.mk_record(type:SSL3_CONTENT_TYPE_HANDSHAKE, version:this.version, epoch:0, seq_no:0, data:msg);
            ret = ssl_parse(blob:rec);
            if (isnull(ret))
              return this.set_error('Failed to parse a decrypted handshake message.');

            # Got a Finished, process it
            if(ret['handshake_type'] ==  SSL3_HANDSHAKE_TYPE_FINISHED)
            {
              # Extract the server's Finished value.
              embedded_srv_finished = ret['data'];

              # Check the embedded Finished value against ours.
              if (srv_finished != embedded_srv_finished)
                return this.set_error('Server Finished value mismatch.');

              # All tests have been passed, so the handshake phase is complete.
              return TRUE;
            }
          } # ccs
        }
        else
          return this.set_error('Received unexpected record content type ' + ctype + '.');
      }
    }

    if(ccs)
      return this.set_error('Server Finished handshake message not received.');
    else
      return this.set_error('ChangeCipherSpec not received.');
  }

  ##
  # Read a record from an established DTLS connection.
  #
  # @param type variable to receive the message content type.
  #
  # @return Record data, or NULL on error.
  ##
  public function recv_msg(&type)
  {
    local_var msg, rec, version;

    if(!isnull(this.errors))
    {
      dbg::log(src: FUNCTION_NAME, msg: "Errors found on the current connection - port " + this.port + ".");
      return NULL;
    }

    # Receive a DTLS record
    rec = this.recv_rec();
    if (isnull(rec))
      return this.set_error('Failed to receive a DTLS record.');

    # Get record type and DTLS protocol version
    type = ord(rec[0]);
    version = ord(rec[1]) * 256 + ord(rec[2]);

    # Check DTLS protocol version
    if (version != this.version)
      return this.set_error('dtls::recv_msg(): DTLS version mismatch.');

    # Decrypt the record
    if(this.epoch >= 1)
    {
      msg = this.decrypt_record(rec);
      if(isnull(msg))
        return this.set_error('dtls::recv_msg(): Failed to decrypt a DTLS record.');
    }
    else msg = substr(rec, 13);

    return msg;
  }

  ##
  # Write data to an established DTLS connection.
  #
  # @param type Record content type
  # @param data Data to be written.
  #
  # @return TRUE on success, NULL on error.
  #
  # @remark Data must be <= MTU.
  ##
  public function send_msg(type, data)
  {
    local_var htype, rec;

    if(!isnull(this.errors))
    {
      dbg::log(src: FUNCTION_NAME, msg: "Errors found on the current connection - port " + this.port + ".");
      return NULL;
    }

    # Encrypt the message
    if(this.epoch >= 1)
    {
      data = this.encrypt_msg(type:type, data:data);
      if(isnull(data))
        return this.set_error('dtls::send_msg(): failed to encrypt a DTLS message.');
    }

    rec = this.mk_record(type:type, data:data);
    if(isnull(rec))
    {
      if(type == SSL3_CONTENT_TYPE_HANDSHAKE)
      {
        htype = ord(data[0]);
        return this.set_error('dtls::send_msg(): failed to create DTLS record for handshake type ' + htype);
      }
      else
        return this.set_error('dtls::send_msg(): failed to create DTLS record for content type ' + type);
    }

    if(!this.testing)
    {
      dbg::log(src: FUNCTION_NAME, msg: 'Sending DTLS message to port ' + this.port +
                                        ', type ' + serialize(type) + ' :', ddata:rec);
      send(socket:this.soc, data:rec);
    }
    else
    {
      this.test_send_buf = rec;
    }

    # ChangeCipherSpec
    if(type == SSL3_CONTENT_TYPE_CHANGECIPHERSPEC)
    {
      this.increment_epoch();
      this.reset_rseq();
    }
    else
      this.increment_rseq();

    return TRUE;
  }

  ##
  # Sets the key for computing a MAC during encryption.
  #
  # @anonparam <first> Raw hexidecimal string key.
  ##
  protected function set_enc_mac_key()
  {
    this.enc_mac_key = _FCT_ANON_ARGS[0];
  }

  ##
  # Sets the key for computing a MAC during decryption.
  #
  # @anonparam <first> Raw hexidecimal string key.
  ##
  protected function set_dec_mac_key()
  {
    this.dec_mac_key = _FCT_ANON_ARGS[0];
  }

  ##
  # Sets the client encryption key.
  #
  # @anonparam <first> Raw hexidecimal string key.
  ##
  protected function set_enc_key()
  {
    this.enc_key = _FCT_ANON_ARGS[0];
  }

  ##
  # Sets the client decryption key.
  #
  # @anonparam <first> Raw hexidecimal string key.
  ##
  protected function set_dec_key()
  {
    this.dec_key = _FCT_ANON_ARGS[0];
  }

  ##
  # Sets the client encryption initialization vector.
  #
  # @anonparam <first> Raw hexidecimal string IV.
  ##
  protected function set_enc_iv()
  {
    this.enc_iv = _FCT_ANON_ARGS[0];
  }

  ##
  # Sets the client decryption initialization vector.
  #
  # @anonparam <first> Raw hexidecimal string IV.
  ##
  protected function set_dec_iv()
  {
    this.dec_iv = _FCT_ANON_ARGS[0];
  }

  ##
  # Sets the length of the computed tag for an authenticated cipher.
  #
  # @anonparam <first> Integer tag length.
  ##
  protected function set_tag_len()
  {
    this.tag_len = _FCT_ANON_ARGS[0];
  }

  ##
  # Sets the key size of the negotiated cipher.
  #
  # @anonparam <first> Integer length of encryption/decryption keys.
  ##
  protected function set_key_size()
  {
    this.key_size = _FCT_ANON_ARGS[0];
  }

  ##
  # Set cipher block size
  #
  # @anonparam <first> Integer block size.
  ##
  protected function set_cipher_block_size()
  {
    this.cipher_block_size = _FCT_ANON_ARGS[0];
  }

  ##
  # Set the negotiated cipher suite.
  #
  # @anonparam <first> Raw hexidecimal string of the cipher.
  ##
  protected function set_cipher()
  {
    this.cipher = _FCT_ANON_ARGS[0];
  }

  ##
  # Set the negotiated cipher description.
  #
  # @anonparam <first> String cipher description.
  ##
  protected function set_cipher_desc()
  {
    this.cipher_desc = _FCT_ANON_ARGS[0];
  }

  ##
  # Set the cipher change epoch counter
  #
  # @anonparam <first> An integer count.
  ##
  protected function set_epoch()
  {
    this.epoch = _FCT_ANON_ARGS[0];
  }

  ##
  # Append a line of text to the error record.
  #
  # @anonparam <first> String error message.
  ##
  protected function add_err_msg()
  {
    this.errors += _FCT_ANON_ARGS[0] + '\n';
  }

  ##
  # Increment the cipher change epoch counter.
  ##
  protected function increment_epoch()
  {
    this.epoch++;
  }

  ##
  # Reset the inter-epoch message sequence count to zero.
  ##
  protected function reset_rseq()
  {
    this.rseq = 0;
  }

  ##
  # Increment the inter-epoch message sequence count.
  ##
  protected function increment_rseq()
  {
    this.rseq++;
  }

  ##
  # Enable testing mode
  #
  # @anonparam <first> Optional boolean flag to indicate we are initialized.
  #
  ##
  protected function enable_test_mode()
  {
    this.testing = TRUE;
    if(!_FCT_ANON_ARGS[0])
      this.init = FALSE;
    else
      this.init = _FCT_ANON_ARGS[0];

    this.test_send_buf = '';
    this.errors = NULL;
  }

  ##
  # Set/add an error message.
  #
  # @anonparam msg The error message.
  # @anonparam ret return value.
  #
  # @return second anonparam.
  ##
  protected function set_error()
  {
    local_var  ret, errmsg;

    errmsg = _FCT_ANON_ARGS[0];
    if(empty_or_null(errmsg))
      errmsg = "set_error() called but no error message was specified.";

    this.add_err_msg(errmsg);

    ret = _FCT_ANON_ARGS[1];

    dbg::log(src: FUNCTION_NAME, msg: errmsg);
    return ret;
  }

  ##
  # Get the description of the negotiated cipher suite.
  #
  # @return the description, or NULL on error.
  ##
  protected function get_cipher_desc()
  {
    local_var cipher, cipher_desc, name;

    if (!isnull(this.cipher_desc))
      return this.cipher_desc;

    cipher = this.cipher;
    name = cipher_name(id:cipher);
    if (isnull(name)) return NULL;

    #ciphers_desc is defined in ssl_funcs.static
    cipher_desc = ciphers_desc[name];
    this.set_cipher_desc(cipher_desc);
    return cipher_desc;
  }

  ##
  # Set DTLS encryption and mac keys.
  #
  # @anonparam keyblk The computed keys
  # @return None.
  ##
  protected function set_keys()
  {
    local_var desc, mac_size, iv_size, key_size, keyblk, pos, tag_len;
    local_var mac, encryption, mode;

    desc = this.get_cipher_desc();
    if (isnull(desc))
      return this.set_error('dtls::set_keys(): Failed to get cipher suite description.');

    keyblk = _FCT_ANON_ARGS[0];

    # Determine the size of the key block's fields.
    mac = cipher_field(name:desc, field:"mac");
    if      ('MD5' >< mac)     mac_size = 16;
    else if ('SHA1' >< mac)    mac_size = 20;
    else if ('SHA256'  >< mac) mac_size = 32;
    else if ('SHA384'  >< mac) mac_size = 48;
    else if ('AEAD' >< mac)    mac_size = 0;
    else
      return this.set_error('dtls::set_keys(): Unsupported hash algorithm in cipher suite description "' + desc + '."');

    encryption = cipher_field(name:desc, field:"encrypt");
    if      ('AES-CBC(128)'  >< encryption) { key_size = 16; iv_size = 16; tag_len = 0; mode = '';}
    else if ('AES-CBC(256)'  >< encryption) { key_size = 32; iv_size = 16; tag_len = 0; mode = '';}
    else if ('3DES-CBC(168)' >< encryption) { key_size = 24; iv_size = 8; tag_len = 0; mode = '';}
    else if ('AES-CCM(128)'  >< encryption) { key_size = 16; iv_size = 4; tag_len = 16; mode = 'CCM';}
    else if ('AES-CCM(256)'  >< encryption) { key_size = 32; iv_size = 4; tag_len = 16; mode = 'CCM';}
    else if ('AES-CCM8(128)'  >< encryption) { key_size = 16; iv_size = 4; tag_len = 8; mode = 'CCM';}
    else if ('AES-CCM8(256)'  >< encryption) { key_size = 32; iv_size = 4; tag_len = 8; mode = 'CCM';}
    else if ('AES-GCM(128)'  >< encryption) { key_size = 16; iv_size = 4; tag_len = 16;  mode = 'GCM';}
    else if ('AES-GCM(256)'  >< encryption) { key_size = 32; iv_size = 4; tag_len = 16;  mode = 'GCM';}
    else
      return this.set_error('dtls::set_keys(): Unsupported encryption algorithm in cipher suite description "' + desc + '."');

    # Ensure the block is big enough.
    if (strlen(keyblk) < 2 * (mac_size + key_size + iv_size))
      return this.set_error('dtls::set_keys(): Key block too small.');

    # Extract the data from the key block.
    pos = 0;
    if('GCM' >!< encryption && 'CCM' >!< encryption)
    {
      this.set_enc_mac_key(substr(keyblk, pos, pos + mac_size - 1)); pos += mac_size;
      this.set_dec_mac_key(substr(keyblk, pos, pos + mac_size - 1)); pos += mac_size;
    }

    this.set_enc_key(substr(keyblk, pos, pos + key_size - 1)); pos += key_size;
    this.set_dec_key(substr(keyblk, pos, pos + key_size - 1)); pos += key_size;

    # DTLSv1 uses explicit IV. These two fields are not used.
    this.set_enc_iv(substr(keyblk, pos, pos + iv_size - 1)); pos += iv_size;
    this.set_dec_iv(substr(keyblk, pos, pos + iv_size - 1));

    if('GCM' >< encryption)
      iv_size = 12;

    if('CCM' >< encryption)
      iv_size = 12;

    this.set_tag_len(tag_len);
    this.set_key_size(key_size);
    this.mode = mode;

    this.set_cipher_block_size(iv_size);
    return TRUE;
  }

  ##
  # This function calculates if a handshake is small enough to send in one datagram.
  #
  # @param handshake - the handshake message to be sent.
  #
  # @return True if the message is too large to send, False if okay.
  ##
  protected function larger_than_mtu(handshake)
  {
    local_var mtu, max_ip_header, udp_header, dtls_record_header;
    mtu = get_kb_item('ICMP/PMTU');
    if(!mtu) mtu = get_kb_item('TCP/PMTU');
    if(!mtu) mtu = 1500;

    if(TARGET_IS_IPV6)
    {
      max_ip_header = 40;
    }
    else
    {
      max_ip_header = 60; # 15*32bits = 480 bits = 60 bytes
    }
    udp_header = 8;
    dtls_record_header = 13;

    return(mtu < (max_ip_header + udp_header + dtls_record_header + strlen(handshake)));
  }

  ##
  # Creates a DTLS record.
  # @param type     - record type.
  # @param version  - DTLS version.
  # @param epoch    - record epoch.
  # @param seq_no   - record sequence number.
  # @param data     - record data.
  #
  # @return         A DTLS record or NULL on error.
  ##
  protected function mk_record(type, version, epoch, seq_no, data)
  {
    local_var rec, len;

    # Defaults.
    if(isnull(version)) version = this.version;
    if(isnull(epoch))   epoch   = this.epoch;
    if(isnull(seq_no))  seq_no  = this.rseq;

    # Check params.
    if (isnull(type)) return NULL;
    if (isnull(epoch)) return NULL;
    if (isnull(seq_no)) return NULL;
    if (isnull(version)) return NULL;
    if (isnull(data)) return NULL;

    type = mkbyte(type);

    version = mkbyte((version >>> 8) & 0xff) + mkbyte(version & 0xff);

    epoch = mkword(epoch);

    seq_no = mkword(0) + mkdword(seq_no);

    len = strlen(data);
    len = mkbyte((len >>> 8) & 0xff) + mkbyte(len & 0xff);

    if (this.larger_than_mtu(handshake:data)) return NULL;

    rec = type + version + epoch + seq_no + len + data;
    return rec;
  }

  ##
  # Receive a DTLS record.
  #
  # @param timeout Socket read timeout.
  #
  # @return A DTLS record, or NULL on error.
  ##
  protected function recv_rec(timeout)
  {
    local_var avail, clen, data, hdr, msg, rec;

    if(isnull(timeout))
      timeout = this.timeout;

    avail = strlen(this.buf);
    if(!this.testing && avail < 13)
    {
      #use recvfrom instead of recv to avoid Nessus "protection" from lost packets
      data = recvfrom(socket:this.soc, port:this.port, timeout:timeout);
      this.set_buf(this.buf + data[0]);
      avail = strlen(this.buf);
    }

    if(avail < 13) return NULL;

    hdr = substr(this.buf, 0, 12);
    this.set_buf(this.buf - hdr);

    avail = strlen(this.buf);
    clen = getword(blob:hdr, pos:11);

    if(!this.testing && avail < clen)
    {
      data = recvfrom(socket:this.soc, port:this.port, timeout:timeout);
      this.set_buf(this.buf + data[0]);
      avail = strlen(this.buf);
    }

    if(avail < clen) return NULL;

    msg = substr(this.buf, 0, clen - 1);
    this.set_buf(this.buf - msg);

    rec = hdr + msg;
    dbg::log(src: FUNCTION_NAME, msg: 'Receiving DTLS message on port ' + this.port + ':\n', ddata:rec);
    return rec;
  }

  ##
  # Decrypt a DTLS record.
  #
  # @anonparam encrypted record.
  #
  # @return decrypted record data (excluding record header).
  ##
  protected function decrypt_record()
  {
    local_var i, len, mac_size, padlen, plain, rec, type;
    local_var encrypted, end, embedded_mac, fragment, mac, start;
    local_var block_size, iv, seq, version, aad;

    if(!this.init)
      return this.set_error('dtls::decrypt_record(): DTLS client not initialized.');

    rec  = _FCT_ANON_ARGS[0];

    version = this.version;
    block_size = this.cipher_block_size;

    # Minimum record length: 13.
    if(isnull(rec) || isnull(block_size) || strlen(rec) < 13 + block_size)
      return this.set_error('dtls::decrypt_record(): invalid input record.');

    type = ord(rec[0]); # record content type
    seq  = substr(rec, 3, 10);

    # Get encrypted part of the record
    encrypted = substr(rec, 13);

    if(this.mode != 'GCM' && this.mode != 'CCM')
    {
      iv = substr(encrypted, 0, block_size -1);
      encrypted = substr(encrypted, block_size);
    }
    else
    {
      iv = this.dec_iv + substr(encrypted, 0, 7);
      encrypted = substr(encrypted, 8);
      aad = seq + mkbyte(type) + mkword(version);
    }

    # Decrypt the record data.
    plain = this.decrypt(data:encrypted, iv:iv, aad:aad);

    if(isnull(plain))
      return this.set_error('Failed to decrypt record data.');

    len = strlen(plain);
    if(this.mode != 'GCM' && this.mode != 'CCM')
    {
      # Get the length of the padding.
      padlen = getbyte(blob:plain, pos:len - 1);
      mac_size = strlen(this.dec_mac_key);

      # Check padlen.
      if (padlen + 1 + mac_size > len)
        return this.set_error('Invalid padlen ' + padlen + '.');

      # Check pad byte.
      # Each pad byte must be the same as the padlen, per DTLS spec.
      for (i = 0; i < padlen; i++)
      {
        if(ord(plain[len - 2 -i]) != padlen)
          return this.set_error('Invalid block cipher padding.');
      }

      # Extract the MAC.
      end = len - (padlen + 1) - 1;
      start = end - mac_size + 1;
      embedded_mac = substr(plain, start, end);

      # Extract decrypted record data.
      end = start - 1;
      start = 0;

      if(end == -1)
        fragment = '';  # Empty record.
      else
        fragment = substr(plain, start, end);

      # Check the embedded MAC against ours.
      mac = this.compute_mac(data:fragment, type:type, client:FALSE, seq:seq);
      if(isnull(mac))
        return this.set_error('Failed to compute the MAC of a decrypted record.');

      if (mac != embedded_mac)
        return this.set_error('dtls::decrypt_record(): MACs do not match.');
    }
    else
    {
      return plain;
    }

    return fragment;
  }

  ##
  # Computes the MAC of the data.
  #
  # @param client Whether the data is from the client or server.
  # @param data The data to be calculate the MAC of.
  # @param type The type of the record.
  # @param seq The sequence number used for computing the MAC.
  # @param version DTLS version.
  #
  # @returns The MAC of the given data, in protocol-specific form.
  ##
  protected function compute_mac(client, data, type, seq, version)
  {
    local_var desc, key, mac;

    if(isnull(seq))
      seq = mkword(this.epoch) + mkword(0) + mkdword(this.rseq);

    if(isnull(version))
      version = this.version;

    if (isnull(client))
      client = TRUE;

    if (client)
      key = this.enc_mac_key;
    else
      key = this.dec_mac_key;

    data = seq + mkbyte(type) + mkword(version) + mkword(strlen(data)) + data;

    desc = this.get_cipher_desc();
    if (isnull(desc))
      return this.set_error('dtls::compute_mac(): Failed to get cipher suite description.');

    mac = cipher_field(name:desc, field:"mac");

    if ('MD5' >< mac)
      return HMAC_MD5(key:key, data:data);
    else if ('SHA1' >< mac)
      return HMAC_SHA1(key:key, data:data);
    else if ('SHA256' >< mac)
      return HMAC_SHA256(key:key, data:data);
    else if ('SHA384' >< mac)
      return HMAC_SHA384(key:key, data:data);
    else if ('AEAD' >< mac)
      return '';
    else
      return this.set_error('dtls::compute_mac(): Unsupported hash algorithm in cipher suite description "' + desc + '."');
  }


  ##
  # Encrypt data with the block cipher.
  #
  # @param data The data to be decrypted.
  # @param iv   Initialization vector for the cipher.
  # @param aad  Additional authentication data for AEAD ciphers.
  #
  # @return The ciphertext of the given data.
  #
  ##
  protected function encrypt(data, iv, aad)
  {
    local_var  block_size, padlen, ret;

    if(this.mode != 'GCM' && this.mode != 'CCM')
    {
      # Calculate how much padding is needed to fill the block.
      block_size = this.key_size;
      padlen = block_size - (strlen(data) % block_size);

      # Append the padding to the data.
      data += crap(data:mkbyte(padlen - 1), length:padlen);
    }

    return this.crypt(data:data, iv:iv, aad:aad, enc:TRUE);
  }


  ##
  # Decrypt data with the block cipher.
  #
  # @param data The data to be decrypted.
  # @param iv   Initialization vector for the cipher.
  # @param aad  Additional authentication data for AEAD ciphers.
  #
  # @return The plain text of the given data.
  ##
  protected function decrypt(data, iv, aad)
  {
    return this.crypt(data:data, iv:iv, aad:aad, enc:FALSE);
  }


  ##
  # Checks whether a cipher is in a list of cipher suites.
  #
  # @anonparam cipher Cipher in question.
  # @anonparam ciphers List of cipher suites.
  #
  # @return TRUE for success, FALSE otherwise.
  ##
  protected function cipher_in_list()
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
  # Encrypt a DTLS message.
  #
  # @param type Message type.
  # @param data Message data.
  # @param version DTLS version.
  # @param seq Sequence number for generating MAC.
  #
  # @return encrypted DTLS message, or NULL on error.
  #
  # @remark mac is attached and encrypted
  ##
  protected function encrypt_msg(type, data, version, seq)
  {
    local_var block_size, iv, mac, msg, aad;

    if(isnull(version))
      version = this.version;

    if(isnull(seq))
      seq  = mkword(this.epoch) + mkword(0) + mkdword(this.rseq);

    block_size = this.cipher_block_size;

    # Compute the MAC of the unencrypted application data.
    mac = '';

    if(this.mode != 'GCM' && this.mode != 'CCM')
    {
      # Explicit IV used in DTLSv1
      iv = rand_str(length:block_size);

      mac = this.compute_mac(data:data, type:type, version:version, seq:seq, client:TRUE);
      if(isnull(mac))
        return this.set_error('dtls::encrypt_msg(): Failed to compute mac.');
    }
    else
    {
      aad = seq + mkbyte(type) + mkword(version);
      iv = this.enc_iv + rand_str(length:block_size - 4);
    }

    # Append the MAC to the data and encrypt everything.
    data = this.encrypt(data: data + mac, iv:iv, aad:aad);
    if(isnull(data))
      return this.set_error('dtls::encrypt_msg(): Failed to encrypt record.');

    # Explicit IV.
    if(this.mode != 'GCM' && this.mode != 'CCM')
    {
      msg = iv + data;
    }
    else
    {
      if(strlen(iv) <= 4)
        return this.set_error('dtls::encrypt_msg(): IV is too short.');

      #Only send the explicit part in counter mode
      msg = substr(iv, 4) + data;
    }

    return msg;
  }

  ##
  # Encrypt or decrypt data.
  #
  # @param data Input data.
  # @param iv   Initialization vector.
  # @param enc  Whether to encrypt (TRUE) or decrypt (FALSE).
  # @param aad  Additional authentication data for AEAD ciphers.
  #
  # @return Result of encrypting or decrypting the given data.
  ##
  protected function crypt(data, iv, enc, aad)
  {
    var desc, key, out, ret, version;
    var header, i;

    desc = cipher_field(name:this.get_cipher_desc(), field:"encrypt");
    if (isnull(desc)) return NULL;

    version = this.version;

    if (enc)
      key = this.enc_key;
    else
      key = this.dec_key;

    if ('AES-CBC(128)' >< desc || 'AES-CBC(256)' >< desc)
    {
      if (enc)
        ret = aes_cbc_encrypt(data:data, key:key, iv:iv);
      else
        ret = aes_cbc_decrypt(data:data, key:key, iv:iv);
    }
    else if ('3DES-CBC(168)' >< desc)
    {
      if (enc)
        ret = tripledes_cbc_encrypt(data:data, key:key, iv:iv);
      else
        ret = tripledes_cbc_decrypt(data:data, key:key, iv:iv);
    }
    else if ('CCM' >< desc || 'GCM' >< desc)
    {
      var type;
      header = aad + mkword(strlen(data));

      if ('GCM' >< desc)
        type = 'aes_gcm';
      else if ('CCM' >< desc)
        type = 'aes_ccm';

      if (enc)
      {
        header = aad + mkword(strlen(data));
        ret = crypto_encrypt(type:type, data:data, key:key, iv:iv, options:{taglen:tag_len, aad:header});

        return ret['ciphertext'] + ret['tag'];
      }
      else
      {
        var tag_end = strlen(data) - 1;
        var tag_start = tag_end - tag_len;

        var tag = substr(data, tag_start + 1, tag_end);
        data = substr(data, 0, tag_start);

        header = aad + mkword(strlen(data));
        ret = crypto_decrypt(type:type, data:data, key:key, iv:iv, options:{taglen:this.tag_len, tag:tag, aad:header});
        return ret;
      }
    }
    else
      return this.set_error('dtls::crypt(): Unsupported encryption algorithm in cipher suite description "' + desc + '."');

    if (isnull(ret)) return NULL;

    return ret[0];
  }

  ##
  # Store data to a buffer.
  #
  # @param buf A reference to the buffer where data is to be stored.
  # @param pos Position within the buffer to store the data.
  # @param data A reference to the data to be stored.
  #
  # @return TRUE on success, FALSE on error.
  #
  ##
  protected function set_data(&buf, pos, &data)
  {
    local_var dlen, i;

    dlen = strlen(data);
    if(pos + dlen > strlen(buf))
      return FALSE;

    for(i = 0; i < dlen; i++)
      buf[pos++] = data[i];

    return TRUE;
  }

  ##
  # Assemble handshake fragments.
  #
  # @param hfrags A reference to a variable holding handshake fragments.
  # @param rec    Bytes from one of the fragment records
  #
  # @return TRUE on success, FALSE on error. If a message record is supplied
  #         a reconstructed message record based on the assembled fragments 
  #         will be returned instead of TRUE.
  #
  # @remark On success, hfrags holds assembled handshake messages.
  ##
  protected function assemble_hs_frags(&hfrags, rec)
  {
    local_var i, j, hlen, htype, fdat, flen, foff;
    local_var buf, chk, f, msg, mseq, n, t;

    # for each hs type
    for (i = 0; i < max_index(hfrags); i++)
    {
      t = hfrags[i];
      # for hs types that have been received
      if(t)
      {
        buf = '';
        # for each hs frag of same type
        n = max_index(t);
        for (j = 0; j < n; j++)
        {
          f = t[j];

          # hs frag must have at least 12 bytes
          if(strlen(f) < 12) return NULL;

          htype = ord(f[0]);
          hlen = get_int24(blob:f, pos:1);
          mseq = getword(blob:f, pos:4);

          # some realistic handshake msg length
          if(hlen > 0x10000) return NULL;

          # first frag
          if(j == 0)
          {
            # allocate assembly buffer
            buf = crap(data:'\x00', length:hlen);

            # if a given hs type has more than one frag
            # make sure the type, length, and seq num
            # are the same
            if(n > 1)
              chk = substr(f, 0, 5);
          }

          if (j > 0 && substr(f, 0, 5) != chk)
            return NULL;

          foff = get_int24(blob:f, pos:6);
          flen = get_int24(blob:f, pos:9);

          # frag must not go beyond hs msg len
          if(foff + flen > hlen) return NULL;

          # frag data
          fdat = substr(f, 12);

          # frag len field must match frag size
          if(flen != strlen(fdat)) return NULL;

          # assemble hs frags
          if(!this.set_data(buf:buf, pos:foff, data:fdat))
            return NULL;
        }

        # create a single hs msg
        msg = this.mk_handshake_msg(
            type            : htype,
            message_seq     : mseq,
            data            : buf);

        if(isnull(msg)) return NULL;

        # store reassembled hs msg
        hfrags[i] = msg;
      }
    }

    if(!isnull(rec))
    {
      buf = '';
      for (i = 0; i < max_index(hfrags); i++)
      {
        if(!isnull(hfrags[i]))
          buf += hfrags[i];
      }

      return substr(rec, 0, 10) + mkword(strlen(buf)) + buf;
    }

    return TRUE;
  }

  ##
  # Create a ClientHello DTLS record.
  #
  # @param version Max supported DTLS version.
  # @param cipherspec Cipher suites supported by the client.
  # @param sessionid DTLS session ID.
  # @param cookie Cookie from HelloVerifyRequest.
  # @param mseq ClientHello message sequence number.
  # @param fragoff Fragment offset to be put in the ClientHello message.
  # @param fraglen Fragment length to be put in the ClientHello message.
  # @param challenge 32-byte client random value.
  # @param compmeths Compression methods supported by the client.
  # @param exts Extensions supported by the client.
  #
  # @return A ClientHello message, or NULL on error.
  ##
  protected function client_hello(version, cipherspec, sessionid, cookie, mseq, fragoff, fraglen, challenge, compmeths, exts)
  {
    local_var hello, msg;

    if (isnull(challenge))
      challenge = dec2hex(num:unixtime()) + rand_str(length:28);

    if (isnull(compmeths))
      compmeths = raw_string(0);

    hello =  mkword(version) +
             challenge +
             mkbyte(strlen(sessionid)) + sessionid +
             mkbyte(strlen(cookie)) + cookie +
             mkword(strlen(cipherspec)) + cipherspec +
             mkbyte(strlen(compmeths)) + compmeths;
    if(exts)
      hello +=  mkword(strlen(exts)) + exts;

    if(isnull(mseq))
      mseq = 0;

    msg = this.mk_handshake_msg(
        type            : SSL3_HANDSHAKE_TYPE_CLIENT_HELLO,
        message_seq     : mseq,
        fragment_offset : fragoff,
        fragment_length : fraglen,
        data            : hello);

    return msg;

  }

  ##
  # Accumulate handshake fragments from a DTLS record.
  #
  # @param rec A reference to the DTLS record.
  # @param hfrags A reference to a variable that stores the handshake fragments.
  # @param hellodone Variable to be set if ServerHelloDone is in the record.
  #
  # @return TRUE on success, FALSE on error.
  ##
  protected function accumulate_hs_frags(&rec, &hfrags, &hellodone)
  {
    local_var f, frags, htype;

    frags = this.get_hs_frags(rec:rec);
    if(isnull(frags)) return FALSE;

    foreach f (frags)
    {
      # Check minimum handshake fragment length
      if(strlen(f) < 12) return FALSE;

      htype = ord(f[0]);
      if(isnull(hfrags[htype]))
        hfrags[htype] = make_list();

      # Accumulate handshake frags of same type
      hfrags[htype] = make_list(hfrags[htype], f);

      # Flag if ServerHelloDone is in the record
      if(htype == 14 && !isnull(hellodone) && !hellodone)
        hellodone = TRUE;
    }

    return TRUE;
  }

  ##
  # Create a DTLS handshake message.
  #
  # @param type            - handshake message type.
  # @param message_seq     - handshake message sequence number.
  # @param fragment_offset - fragment offset.
  # @param fragment_length - fragment length.
  # @param data            - handshake message data.
  #
  # @return                a handshake message or NULL on error.
  ##
  protected function mk_handshake_msg(type, message_seq, fragment_offset, fragment_length, data)
  {
    local_var len, msg;

    # Sanity Checks
    if (isnull(type)) return NULL;
    if (isnull(message_seq)) return NULL;

    if (isnull(fragment_offset))
       fragment_offset = raw_string(0x00, 0x00, 0x00);
    else
       fragment_offset = substr(mkdword(fragment_offset), 1);

    type = mkbyte(type);

    len = strlen(data);
    len = mkbyte((len >>> 16) & 0xff) + mkbyte((len >>> 8) & 0xff) + mkbyte(len & 0xff);

    message_seq = mkword(message_seq);

    if (isnull(fragment_length))
       fragment_length = len;
    else
       fragment_length = substr(mkdword(fragment_length), 1);

    msg = type + len + message_seq + fragment_offset + fragment_length + data;

    return msg;
  }

  ##
  # Get all handshake fragments within a DTLS record.
  #
  # @param rec A reference to a DTLS record.
  #
  # @return A list of handshake fragments, or NULL on error.
  #
  # @remark A handshake fragment refers to the Handshake structure in RFC 4347.
  ##
  protected function get_hs_frags(&rec)
  {
    local_var i, frags, rlen;
    local_var clen, ctype;
    local_var hend, hlen, hpos, flen;

    rlen = strlen(rec);

    # Minimum record size: 13
    if (rlen < 13) return NULL;

    # Check record content length
    clen = getword(blob:rec, pos:11);
    if(13 + clen != rlen) return NULL;

    # Check record content type to make sure
    # it's a handshake frag.
    ctype = getbyte(blob:rec, pos:0);
    if(ctype != SSL3_CONTENT_TYPE_HANDSHAKE) return NULL;

    # Handshake frag starts at pos 13
    hpos = 13;
    i = 0;
    frags = [];
    while (hpos < rlen)
    {
      # Minimum handshake frag size: 12
      if(hpos + 12 > rlen)
        return NULL;

      # Fragment length
      flen = get_int24(blob:rec, pos:hpos + 9);

      # Check fragment length
      hend = hpos + 12 + flen;
      if(hend > rlen) return NULL;

      # Get handshake frag
      frags[i++] = substr(rec, hpos, hpos + 12 + flen -1);

      # Next handshake frag if any
      hpos = hend;
    }

    return frags;
  }
}

##
# Returns a DTLS object for the socket if one exists.
#
# @param soc  An open DTLS socket.
#
# @return The DTLS object for the given socket.
##
function _get_dtls_state(soc)
{
  if(!soc)
    return NULL;

  return _dtls[string(soc)];
}

# Non-object wrapper functions intended to bolt into existing TLS uses.

##
# Get error message(s).
#
# @param soc Socket opened for DTLS connection.
# @return Errors on this socket.
##
function dtls_get_error(soc)
{
  var dtls = _get_dtls_state(soc:soc);

  if(isnull(dtls))
    return 'Error: \nDTLS state not associated with supplied socket.';

  return 'Error(s): \n' + dtls.errors;
}

##
# Clear DTLS read buffer
#
# @param soc Socket opened for DTLS connection.
#
# @return Returns nothing
##
function dtls_clear_buf(soc)
{
  var dtls = _get_dtls_state(soc:soc);

  if(!dtls)
  {
    dbg::log(src: FUNCTION_NAME, msg: "No state object supplied.  DTLS state is required.");
    return NULL;
  }

  dtls.set_buf('');
}

##
# Open a UDP socket and initialize the dtls structure for this port.
#
#
# @anonparam port The UDP port to attempt connecting to.
#
# @param encaps The DTLS encapsulation protocol to negotiate.
#
# @return Returns the opened socket
##
function open_sock_dtls(encaps)
{
  var soc, dtls, port;

  # Sanity check parameters.
  if (max_index(_FCT_ANON_ARGS) != 1)
  {
    dbg::log(src:FUNCTION_NAME, msg:'function called with the wrong number of arguments.');
    return NULL;
  }

  port = _FCT_ANON_ARGS[0];

  soc = open_sock_udp(port);
  if(! soc)
  {
    dbg::log(src:FUNCTION_NAME, msg:'failed to open socket on port ' + serialize(port) + ' for DTLS.');
    return NULL;
  }

  if (!socket_ready(soc))
  {
    dbg::log(src:FUNCTION_NAME, msg:'socket on port ' + serialize(port) + ' is not ready.');
    close(soc);
    return NULL;
  }

  if(isnull(encaps))
    encaps = DTLS_10;

  # We only support DTLSv1 and DTLSv1.2
  if(encaps != DTLS_10 && encaps != DTLS_12)
  {
    dbg::log(src:FUNCTION_NAME, msg:'DTLS version ' + hexstr(mkdword(encaps)) + ' is not supported.');
    return NULL;
  }

  dtls = new("dtls", soc, port);
  dtls.set_version(encaps);

  _dtls[string(soc)] = dtls;
  return soc;
}

##
# Close the DTLS connection
#
# @param soc Socket opened for DTLS connection.
# @return None.
##
function dtls_disconnect(soc)
{
  #socket will be closed when dtls object is destroyed
  if(soc)
    _dtls[string(soc)] = NULL;
}

##
# Perform DTLS handshake.
#
# @param soc Socket opened for DTLS connection.
# @param suites A list of cipher suite IDs to support.
# @param exts DTLS extensions to send in ClientHello.
# @param timeout Socket recv timeout.
#
# @return TRUE on success, NULL on error.
##
function dtls_connect(soc, suites, exts, timeout)
{
  local_var dtls;

  dtls = _get_dtls_state(soc:soc);
  if(isnull(dtls))
  {
    dbg::log(src: FUNCTION_NAME, msg: "No DTLS object found for socket.");
    return NULL;
  }

  dtls.init(suites:suites, exts:exts, timeout:timeout);

  if(!dtls.init)
  {
    dbg::log(src: FUNCTION_NAME, msg: "DTLS initialization failed.");
    return NULL;
  }

  return dtls.connect();
}


##
# Perform the version negotiation part of a DTLS handshake only.
#
# @param soc Socket opened for DTLS connection.
# @param suites A list of cipher suite IDs to support.
# @param exts DTLS extensions to send in ClientHello.
# @param timeout Socket recv timeout.
#
# @return Returns an array of ServerHello message responses, NULL on error.
##

function do_client_hello(soc, suites, exts, timeout)
{
  local_var dtls, hfrags, ret, clt_random;

  dtls = _get_dtls_state(soc:soc);
  if(isnull(dtls))
  {
    dbg::log(src: FUNCTION_NAME, msg: "No DTLS object found for socket.");
    return NULL;
  }

  dtls.init(suites:suites, exts:exts, timeout:timeout);

  if(!dtls.init)
  {
    dbg::log(src: FUNCTION_NAME, msg: "DTLS initialization failed.");
    return NULL;
  }

  hfrags = [];

  clt_random = dec2hex(num:unixtime()) + rand_str(length:28);

  ret = dtls.do_client_hello(hfrags:hfrags, clt_random:clt_random);
  if(ret)
    return hfrags;

  return NULL;
}


##
# Read a record from an established DTLS connection.
#
# @param soc Socket opened for DTLS connection.
# @param type variable to receive the message content type.
#
# @return Record data, or NULL on error.
##
function dtls_recv_msg(soc, &type)
{
  local_var dtls = _get_dtls_state(soc:soc);

  if(!dtls || !dtls.init)
  {
    dbg::log(src: FUNCTION_NAME, msg: "No state object supplied.  DTLS state is required.");
    return NULL;
  }

  return dtls.recv_msg(type:type);
}

##
# Write data to an established DTLS connection.
#
# @param soc Socket opened for DTLS connection.
# @param type Record content type
# @param data Data to be written.
#
# @return TRUE on success, NULL on error.
#
# @remark Data must be <= MTU.
##
function dtls_send_msg(soc, type, data)
{
  local_var htype, rec, dtls;

  dtls = _get_dtls_state(soc:soc);

  if(!dtls || !dtls.init)
  {
    dbg::log(src: FUNCTION_NAME, msg: "No state object supplied.  DTLS state is required.");
    return NULL;
  }

  return dtls.send_msg(type:type, data:data);
}
