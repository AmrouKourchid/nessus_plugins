#TRUSTED 40189e914c0932cd3b82a649b5b07c568ebe88ce90c9ce6f2e3f403b079ef310f44dcbdc04e8893887e40a7cf2ff6cd3bfe3aaa0a11573a9fa35385fd01a9a1f0e3492e6c2ba13c644684126a38bd3684512c297955fdde974d25e351d2c49fdfe1bd25832b9a5d580e02799a8df71606fd18ac0ae9f999f618f1fc647ee6ac75997b97a51b3135d97e9a37c8a4ece2340a6cd285127287ad9ab67472dcf27af668daeacd2a35901015754e823a5466eae7142caa78a88bff29e254a200830c18178fc737e6ac514f562a6999d186361ebe292ec6805627178911e78df21231caa6593bceb28e1ed18cad52a1824798c0d3f12e2523b507d307222f307535a0d8a3f2dce7db9dfcb434f77f255a0f209e2b11503e5f0b9fe468ed199592e9e1bb577912de7e834bd3c6a38a66b5e2be15c808515ec9a286464e6786504fa929d0ea0f40c6bc5e1e5e08cef16a4ec87e35937cb82d7728b5e78b12c775753c1635008965d834f1e780850a7bca36a67cd3093c7c292708300b6945a7b0e8220b2871cd53487607c96e44d9472d88ca8cf7131c9334965b5d60520172fc037335ee3690583ffd147845f23000cd63386b9f6db79687d7e91d6c314db9cfe27901df9982ef30c728f1efbe7dc27bdae6ca720f281bf8f1eb64fef468cc153924582f9209c1ef011f640bcb7797348d994eb313a54a6b2682b1906be22db0e776265
#TRUST-RSA-SHA256 499ddaa67bfb422818a873de8f63a0642c3c739b864f60b1cfb4e1512e9983757b3e3193e22fc751d6d8d81a873bbbe9e672da2341c70fe5cc627a487d9f3ee4c49152cb6f98c447cd792d3804e04d1bc538f8169f224472ccfbd50b2abaf0f5c82ca2dfdbaa02e1c14b427e20aef2f184fdaf76390034c506b6aff008d442920959ef5cbc86765d4e9376c79a9caf73341ac692beaa4514ef2292d8c40e8845b56d8e4e33864a4975773ebfa469e03dcc46848bdc19d26bfd1ded9f591709b6c8272ec2c0d65b6a79b7db4f573f0301914a4373dfe4a4cfdbc4476266514c41c8339579f4dfe599b35685b2cfba1e5167f30de71f9f687aafe0508f975ab181e6e1c49063ac697f3548021cbf2df68cbb9c74ea341a7069910f68132874e92e0ff816379e2afac240187b9af30c48c1a77920801fb73c7c1f34f8e2e22b887b13a1edbcf22eeb5d5f0814415d807ea50684ccfec7360c0003d7ccbf388dc0a8003a7b983f737946c86f131e423d78487a1d0f16499b057e43f84f8a0f65c873773f8bb9bc78a88b38c1859a1dcf84a66d4b1070d652b6cdd9742633f8b5a74f58e50f061a59f21be093f6da7b0443b8d63f197b596e48e0598bdeb41cf898875549231e72e70f78d11b735a3da91fb3cac5617c9aa3835a8d7748abcaa6f61b83e438ec18fcdf909030d41910c94a321c5a25f23ff6043d5f2cec687fc31ec5
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84821);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/11");

  script_name(english:"TLS ALPN Supported Protocol Enumeration");
  script_summary(english:"Enumerates TLS ALPN supported protocols.");

  script_set_attribute(attribute:"synopsis",value:
"The remote host supports the TLS ALPN extension.");
  script_set_attribute(attribute:"description",value:
"The remote host supports the TLS ALPN extension. This plugin
enumerates the protocols the extension supports.");
  script_set_attribute(attribute:"see_also",value:"https://tools.ietf.org/html/rfc7301");
  script_set_attribute(attribute:"solution",value:"n/a");
  script_set_attribute(attribute:"risk_factor",value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/17");

  script_set_attribute(attribute:"plugin_type",value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  # Allow this to run for at least 20 minutes
  if (int(get_preference("plugins_timeout")) <= 1200 &&
      int(get_preference("timeout.84821")) <= 1200)
    script_timeout(1200);

  script_copyright(english:"This script is Copyright (C) 2015-2024 Tenable Network Security, Inc.");

  script_dependencies("ssl_supported_versions.nasl", "find_service_dtls.nasl");
  script_require_ports("SSL/Supported", "DTLS/Supported");
  script_exclude_keys("global_settings/disable_ssl_cipher_neg");
  exit(0);
}

include("byte_func.inc");
include("ftp_func.inc");
include("kerberos_func.inc");
include("ldap_func.inc");
include("nntp_func.inc");
include("smtp_func.inc");
include("telnet2_func.inc");
include("rsync.inc");
include("ssl_funcs.inc");

if ( get_kb_item("global_settings/disable_ssl_cipher_neg" ) ) exit(1, "Not negotiating the SSL ciphers per user config.");

if(!get_kb_item("SSL/Supported") && !get_kb_item("DTLS/Supported"))
  exit(1, "Neither the 'SSL/Supported' nor the 'DTLS/Supported' flag is set.");

var pp_info = get_tls_dtls_ports(fork:TRUE, dtls:TRUE);
var port = pp_info["port"];
if (isnull(port))
  exit(1, "The host does not appear to have any TLS or DTLS based services.");

if(pp_info["proto"] == "tls")
{
  # https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#alpn-protocol-ids
  var protocols = make_list("http/1.1", "spdy/3.1", "spdy/2", "spdy/3", "h2", "h3",
                            "h2c", "ftp", "imap", "pop3", "smb", "nntp", "tds/8.0",
                            "sip/2", "irc");

  if(thorough_tests)
  {
    protocols = make_list(protocols,
      # these are additional non-iana registered protocols that are used in mod_h2, IIS 10, or
      # sent by firefox/chrome
      "spdy/1", "h2-14", "h2-15", "h2-16",

      # and these are the rest of the protocols specified by IANA. at least these are the ones
      # that wouldn't be UDP only  - they should be less common.
      '\x0A\x0A', '\x1A\x1A', '\x2A\x2A', '\x3A\x3A',
      '\x4A\x4A', '\x5A\x5A', '\x6A\x6A', '\x7A\x7A',
      '\x8A\x8A', '\x9A\x9A', '\xAA\xAA', '\xBA\xBA',
      '\xCA\xCA', '\xDA\xDA', '\xEA\xEA', '\xFA\xFA', 
      "http/0.9", "http/1.0", "stun.turn", "stun.nat-discovery",
      "managesieve", "coap", "xmpp-client", "xmpp-server",
      "acme-tls/1", "mqtt", "ntske/1", "sunrpc",
      "nnsp", "doq", "dicom", "grpc-exp");
  }

  var versions = get_kb_list('SSL/Transport/'+port);
  var add_curve_exts = FALSE;
  var cipherspec, alpn_ciphers;

  var tls10 = tls11 = tls12 = tls13 = 0;
  if(! isnull(versions))
  {
   foreach var encap (versions)
   {
     if (encap == ENCAPS_TLSv1)              tls10 = 1;
     else if (encap == COMPAT_ENCAPS_TLSv11) tls11 = 1;
     else if (encap == COMPAT_ENCAPS_TLSv12) tls12 = 1;
     else if (encap == COMPAT_ENCAPS_TLSv13) tls13 = 1;
   }
  }

  if(!(tls10 || tls11 || tls12 || tls13))
    exit(0, 'The SSL-based service listening on ' + pp_info["l4_proto"] + ' port '+port+' does not appear to support TLSv1.0 or above.');

  # use latest version available
  var version;
  if(tls13)
    version = COMPAT_ENCAPS_TLSv13;
  else if (tls12)
    version = COMPAT_ENCAPS_TLSv12;
  else if (tls11)
    version = COMPAT_ENCAPS_TLSv11;
  else if (tls10)
    version = ENCAPS_TLSv1;

  if(!tls13)
  {
    alpn_ciphers = get_valid_ciphers_for_encaps(encaps:version, ciphers:ciphers);
    if(is_ec_extension_required(cipher_set:alpn_ciphers, encaps:version) && !tls13)
      add_curve_exts = TRUE;
    cipherspec = get_cipherspec_from_names(ciphernames:keys(alpn_ciphers));
  }
  else
  {
    cipherspec = ciphers["TLS13_AES_128_GCM_SHA256"];
  }
}
else if(pp_info["proto"] == "dtls")
{
  # the following are alpn protocol ids for STUN and TURN - ietf RFC-7443
  # https://tools.ietf.org/html/rfc7443
  # and WebRTC https://tools.ietf.org/html/draft-ietf-rtcweb-alpn-04
  protocols = make_list("stun.nat-discovery", "stun.turn", "webrtc", "c-webrtc",
                        "coap", "mqtt", "dot", "sunrpc", "h3", "doq", "sip/2",
                        "dicom");

  versions = get_kb_list('DTLS/Transport/' + port);
  if(isnull(versions))
    exit(0, 'The DTLS service listening on ' + pp_info["l4_proto"] + ' port ' + port + ' does not appear to use a supported version.');

  version = COMPAT_ENCAPS_TLSv11;
  cipherspec = dtls10_ciphers;
  foreach encap(versions)
  {
    if(encap == COMPAT_ENCAPS_TLSv12)
    {
      version = COMPAT_ENCAPS_TLSv12;
      cipherspec = dtls12_ciphers;
      break;
    }
  }

  add_curve_exts = TRUE;
}
else
  exit(1, "A bad protocol was returned from get_tls_dtls_ports(). (" + pp_info["port"] + "/" + pp_info["proto"] + ")");

var report = '';
var exts, info, recs;
foreach var protocol (protocols)
{
  exts = tls_ext_alpn(make_list(protocol));

  if(add_curve_exts)
    exts += tls_ext_ec() + tls_ext_ec_pt_fmt() + tls_ext_sig_algs();

  if(pp_info["proto"] == "tls")
    recs = get_tls_server_response(port:port, encaps:version, cipherspec:cipherspec, exts:exts);
  else
    recs = get_dtls_server_response(port:port, encaps:version, cipherspec:cipherspec, exts:exts);

  if(!recs)
    continue;

  info = ssl_find(
    blob:recs,
    tls13:tls13,
    'content_type', SSL3_CONTENT_TYPE_HANDSHAKE,
    'handshake_type', SSL3_HANDSHAKE_TYPE_SERVER_HELLO
  );

  if(empty_or_null(info['extension_alpn_protocol']) && tls13)
  {
    info = ssl_find(
      blob:recs,
      tls13:tls13,
      'content_type', SSL3_CONTENT_TYPE_HANDSHAKE,
      'handshake_type', TLS13_HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS
    );
  }

  if (!isnull(info['extension_alpn_protocol']) && info['extension_alpn_protocol'] == protocol)
  {
    set_kb_item(name:"SSL/ALPN/" + port, value:info['extension_alpn_protocol']);
    report += '\n  ' + info['extension_alpn_protocol'];
  }
}

if(report != '')
  security_report_v4(port:port, proto:pp_info["l4_proto"], severity:SECURITY_NOTE, extra:report);
else
  exit(0, "No ALPN extension protocols detected on " + pp_info["l4_proto"] + " port " + port + ".");
