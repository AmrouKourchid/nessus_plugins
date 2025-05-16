#TRUSTED 78dfd7ce45438891b9f16b9964da9c093ae724f252a772a82f2f1e5d3c5a1b2bbaa303eab777bb1466b1c2a96b0975876f4beffb1efd0a4725cd8acf82e314f2c2a5ba2c0e6b62453fbf7a185459651befaefebbf3b42b486b82e5e15710dffebe503d65d3905bb6bc865c1c1d45170491daaaef9c5fe484a5254be10fad0377725e40c7fec842fb564999c6c8c4680c90be2536a75e1bd3bb37a1e2c1e0814ddfe709365eae6bbc50eb3a92a167f33e223d9ff67c89383ef731b6c7b9ef533b601030d61f454d78909cb2c00614df82adde39816464b29a58dc38b5f3c42111daf292726b11c4847aada68e3822c723c947a46c206276c0269f0ef8ec674bf3c943c50615cd82d63b938b90072be9db551b0a64bb23fa64895fdda03dcd4a63a6fc598c981203d3a8f9aa244485477f924a7c112463693049dba55404d51dce5d7c4e9c25d434866e336a9de0bc0cc5aad1cf4c6c1e8730054a4e60b9b99671279ab6cf48ee93c2da3f636e820891efa7afad500b32cc5311263b115e25098d23608b91cc96b9e44f8f3cbe530f21d91aa9c13c214e1f51f97892b4eead02d7ec1eff36774b57ad69e21b84a5f63f043c4c1526943f42f93484ad2fd806160a550bd7e0d8b65f4e9ebd11ac2717b29baef600568b34a9f0f3a8b000f9b3d1cb03af865e7c10bef91890eca01b0b61a19cf07dd2d51a95e4f746086fb7e38409
#TRUST-RSA-SHA256 af5b474de4de34e711a35eb317d46b3727224f7998b56cee0abc1ceca9f6b9badabafa556cabd3d4807875805a8ecab26dcd8ac39fb55262f9572cdf8ee72a21e227eb3ffceae536ad1b0fe94720ab096573169633c80f8696e0cefb7fe6d468c84339ee45af7710fc1023b2a55bab64e689dd4229572f4d62fbb8e94b6ca4144f5011c80d0758eb29afbed1c50b7ac252ab054fcc2a921dee43d698fdfab045f101ed6920b4277c1c9823fb248f940a8d30b736b8689a0b876d8dbaa9d14a5a2b0086121bd5b47e720b344c4fdea8a98b7fa094198a9123ddbf91ff87251e5dc80186fe55b79455b2526f3ed4daa2d97e96ba443ba7002c9ef9c78a136bdd468a1e515276f1006b462d5dc46934ef70c4f87a91925e2c27bfc45fe198878262a18019af68d376e348b8a35804486fd9f23128e6e78d9c32d23c2fa0eee75c4e1b5aeaf80c676038b39c04a9ee49723b4f1040cd6c489d0f5fa8f4ec1c002986ca6a8593d695755dcd53af1add1971a48bc306a21a4ddb5c63c791faa3f0191a0065e7f3df44e181ee4225ce298989fbe165257fe84d0482dcafb0b60e5055268af4e200ce54538f98409fbef2b6e8e1dfc0f525ee815b1172b2b6b53cc01d2fa6f299ceea8fffa21b6577a0b388235f5eea77d69add18f3fbe8391a026ea587f449e03a1d1ef7365fac72e9cbb9a628e03910cbdf58da39d8badd17933672ed
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(21643);
  script_version("1.85");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/11");

  script_name(english:"SSL Cipher Suites Supported");
  script_summary(english:"Checks which SSL cipher suites are supported.");

  script_set_attribute(attribute:"synopsis", value:
"The remote service encrypts communications using SSL.");
  script_set_attribute(attribute:"description", value:
"This plugin detects which SSL ciphers are supported by the remote
service for encrypting communications.");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/docs/man1.0.2/man1/ciphers.html");
  # https://web.archive.org/web/20171007050702/https://wiki.openssl.org/index.php/Manual:Ciphers(1)
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e17ffced");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2006/06/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2006-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssl_supported_versions.nasl", "find_service_dtls.nasl");
  script_require_ports("SSL/Supported", "DTLS/Supported");

  script_timeout(60 * 60);

  exit(0);
}

include('byte_func.inc');
include('ftp_func.inc');
include('kerberos_func.inc');
include('ldap_func.inc');
include('nntp_func.inc');
include('smtp_func.inc');
include('ssl_funcs.inc');
include('telnet2_func.inc');
include('rsync.inc');


##
# We want to format the cipher report returned from cipher_report()
# We are simply removing the SSL version in each strength section
# @remark The param 'report' is assumed to be already formatted by 'cipher_report()'
# @param report A report from 'cipher_report()'
# @return A modified report
##
function format_cipher_report(report)
{
  local_var regex, version;

  regex = make_list("(\s)+(SSLv2)\s", "(\s)+(SSLv3)\s", "(\s)+(TLSv1)\s",
                    "(\s)+(TLSv11)\s", "(\s)+(TLSv12)\s");

  foreach version (regex)
      report = ereg_replace(pattern:version, replace:'\n', string:report);

  return report;
}


##
# Identifies the cipher or ciphers supported by an SSL server as
# entries in a list of possible cipher suites.
#
# @param <rec:array>     Supported cipher information returned by server.
# @param <ciphers:array> Array of possible SSL/TLS cipher suites.
#
# @return A list of supported ciphers as keys in the 'ciphers' array.
##
function get_received_ciphers(rec, ciphers)
{
  local_var str, srv_cipher;

  result = make_list();

  # Old protocols return a list of ciphers, which can either be
  # a subset of the ones we sent (we only send one), or a subset
  # of the ciphers it supports. We'll be conservative and store
  # all ciphers returned.
  foreach srv_cipher (rec["cipher_specs"])
  {
    if (encaps == ENCAPS_SSLv2)
    {
      str = raw_string(
        (srv_cipher >> 16) & 0xFF,
        (srv_cipher >>  8) & 0xFF,
        (srv_cipher >>  0) & 0xFF
      );
    }
    else
    {
      str = raw_string(
        (srv_cipher >>  8) & 0xFF,
        (srv_cipher >>  0) & 0xFF
      );
    }

    foreach var known_cipher (keys(ciphers))
    {
      if (str == ciphers[known_cipher] && !isnull(ciphers[known_cipher]))
        result = make_list(result, known_cipher);
    }
  }

  return result;
}

##
# Make the ciphers array for a ClientHello message based on an array
# of cipher suites.
#
# @param <cipher_set:array> The array of ciphers to encode
# @param <encaps:string>    The protocol being tested
# @return A raw string to use with ClientHello
##
function create_client_hello_ciphers(cipher_set, encaps)
{
  var client_hello_bytes;
  var cipher;

  foreach cipher (sort(keys(cipher_set)))
  {
    if (!isnull(cipher_set[cipher]))
      client_hello_bytes += cipher_set[cipher];
  }

  return client_hello_bytes;
}

##
# Send a ClientHello offering a set of supported SSL/TLS cipher suites.
# Accept the ServerHello response which should contain at least one agreed
# upon cipher if the server supports one of the offered suites.
#
# @param  <cipher_to_check:array> The array of cipher suites offered to the server.
# @param  <encaps:int>            The protocol being tested.
# @param  <port:int>              The port the server is listening on.
# @param  <known_ciphers:int>     A count of the cipher suites discovered so far.
# @param  <dtls:bool>             Is this a DTLS UDP port?
#
# @return An array of information about the cipher suite selected by the server.
##
function test_for_ssl_support(ciphers_to_check, encaps, port, known_ciphers, dtls)
{
  # When we fail to open a socket, we'll pause for a few seconds and
  # try again. We'll only do this so many times before we consider the
  # service too slow, however.
  var at_least_one_successful_connection = FALSE;
  var secure_renegotiation = FALSE;
  var exts = "";
  var soc;
  var ssl_ver;
  var fn = "test_for_ssl_support() - ";

  if(isnull(dtls))
    dtls = FALSE;

  if(isnull(known_ciphers))
    known_ciphers = 0;

  if(isnull(ciphers_to_check) || isnull(encaps) || isnull(port))
    return NULL;

  if(dtls)
  {
    if(encaps == COMPAT_ENCAPS_TLSv11)
      ssl_ver = raw_string(0xfe, 0xff);
    else if(encaps == COMPAT_ENCAPS_TLSv12)
      ssl_ver = raw_string(0xfe, 0xfd);
    else
    {
      ssl_dbg(src:fn,msg: "Attempt to use DTLS with an unsupported encapsulation (" + encaps + ") on port " + port + ".");
      return NULL;
    }
  }
  else
  {
    if (encaps == ENCAPS_SSLv2)      ssl_ver = raw_string(0x00, 0x02);
    else if (encaps == ENCAPS_SSLv3) ssl_ver = raw_string(0x03, 0x00);
    else if (encaps == ENCAPS_TLSv1) ssl_ver = raw_string(0x03, 0x01);
    else if (encaps == COMPAT_ENCAPS_TLSv11) ssl_ver = raw_string(0x03, 0x02);
    else if (encaps == COMPAT_ENCAPS_TLSv12) ssl_ver = raw_string(0x03, 0x03);
    # note TLS 1.3 is handled separately below
  }

  if (encaps >= ENCAPS_TLSv1)
  {
    if(encaps < COMPAT_ENCAPS_TLSv13)
    {
      if(is_ec_extension_required(cipher_set:ciphers_to_check, encaps:encaps))
        exts = tls_ext_ec() + tls_ext_ec_pt_fmt();

      # Include an SNI extension if it makes sense to
      var host = get_host_name();
      if (host != get_host_ip() && host != NULL)
         exts += tls_ext_sni(hostname:host);

      if (encaps == COMPAT_ENCAPS_TLSv12)
        exts += tls_ext_sig_algs();
    }
  }

  if (encaps >= ENCAPS_SSLv3)
  {
    secure_renegotiation = TRUE;
  }

  if (exts == "")
    exts = NULL;

  var cipher_message = create_client_hello_ciphers(cipher_set:ciphers_to_check, encaps:encaps);
  var rec, recs;

  var test_mode = FALSE;
  var tls13 = FALSE;

  if(dtls)
  {
    if (get_kb_item("TEST_dtls_in_flatline"))
      test_mode = TRUE;

    recs = get_dtls_server_response(port:port, encaps:encaps, cipherspec:cipher_message,
                                    exts:exts, test_mode:test_mode,
                                    securerenegotiation:secure_renegotiation);
  }
  else
  {
    if (get_kb_item("TEST_ssl_supported_ciphers_do_not_open_socket"))
      test_mode = TRUE;
    else
    {
      var pauses_taken = 0;

      # Connect to the port, issuing the StartTLS command if necessary.
      while (!(soc = open_sock_ssl(port)))
      {
        pauses_taken++;
        if (pauses_taken > 5)
        {
          if (at_least_one_successful_connection)
            set_kb_item(name:"scan_interference/ssl_supported_ciphers", value:port);
          ssl_dbg(src:fn,msg:"Failed to connect to port " + port + " too "+
            "many times, exiting.");
          exit(1, "Failed to connect to " + port + " too many times.");
        }
        else
        {
          ssl_dbg(src:fn,msg:"Failed to connect to port " + port + ", " +
            "pausing before retrying.");
          replace_kb_item(name:"ssl_supported_ciphers/pauses_taken/" + port, value:pauses_taken);
          sleep(pauses_taken * 2);
        }
      }
    }

    at_least_one_successful_connection = TRUE;

    # Connect to the port, issuing the StartTLS command if necessary.
    recs = get_tls_server_response(soc:soc, port:port, encaps:encaps, cipherspec:cipher_message,
                                            exts:exts, test_mode:test_mode,
                                            securerenegotiation:secure_renegotiation);

    if (!isnull(recs) && encaps == COMPAT_ENCAPS_TLSv13)
    {
      tls13 = TRUE;
      ssl_ver = raw_string(3,3);
    }

    if(soc && !test_mode)
      close(soc);
  }

  if (encaps == ENCAPS_SSLv2)
  {
    rec = ssl_find(
      blob:recs,
      tls13:tls13,
      "content_type", SSL2_CONTENT_TYPE_SERVER_HELLO
    );
  }
  else
  {
    rec = ssl_find(
      blob:recs,
      tls13:tls13,
      "content_type", SSL3_CONTENT_TYPE_HANDSHAKE,
      "handshake_type", SSL3_HANDSHAKE_TYPE_SERVER_HELLO
    );
  }

  if (isnull(rec))
  {
    ssl_dbg(src:fn, msg:"No records received.");
  }
  # Ensure that the SSL version is what we expect.
  else if (rec["version"] != getword(blob:ssl_ver, pos:0))
  {
    ssl_dbg(src:fn, msg:"record version (" + rec["version"] + ") doesn't match " + ssl_ver);
    rec = NULL;
  }
  else if (isnull(rec['cipher_specs']) && !isnull(rec['cipher_spec']))
  {
    rec['cipher_specs'] = make_list(rec['cipher_spec']);
  }

  return rec;
}

##
# Remove the cipher_report() footer. We only need one
# cipher_list_size will determine how many times we remove the footer.
# @remark The param 'report' is assumed to be already formatted by 'cipher_report()'
# @param report A report from 'cipher_report()'
# @param cipher_array_size Length of supported_ciphers array.
# @return A modified report
##
function remove_footer(report, cipher_array_size)
{
  local_var footer, tmp;

  # If the size is only 1 then we do not want to remove the footer
  if (cipher_array_size == 1 ) return report;

  footer ='
The fields above are :

  {Tenable ciphername}
  {Cipher ID code}
  Kex={key exchange}
  Auth={authentication}
  Encrypt={symmetric encryption method}
  MAC={message authentication code}
  {export flag}';

  # Remove the footer except for one hence the '-1'
  tmp = str_replace(string:report, find:footer, replace:'', count:cipher_array_size-1);

  return tmp;
}

if ( get_kb_item("global_settings/disable_ssl_cipher_neg" ) )
  exit(1, "Not negotiating the SSL ciphers, per user config.");

if(!get_kb_item("SSL/Supported") && !get_kb_item("DTLS/Supported"))
  exit(1, "Neither the 'SSL/Supported' nor the 'DTLS/Supported' flag is set.");

set_byte_order(BYTE_ORDER_BIG_ENDIAN);

# Get a port to operate on, forking for each one.
is_dtls = FALSE;
pp_info = get_tls_dtls_ports(fork:TRUE, dtls:TRUE, check_port:TRUE);
port = pp_info["port"];
if (isnull(port))
  exit(1, "The host does not appear to have any TLS or DTLS based services.");

# If it's encapsulated already, make sure it's a type we support.
if(pp_info["proto"] == "tls")
{
  is_dtls = FALSE;
  encaps = get_kb_item("Transports/TCP/" + port);
}
else if(pp_info["proto"] == "dtls")
{
  is_dtls = TRUE;
  encaps = get_kb_item("Transports/UDP/" + port);
}
else
  exit(1, "A bad protocol was returned from get_tls_dtls_ports(). (" + pp_info["port"] + "/" + pp_info["proto"] + ")");

if (encaps > ENCAPS_IP && (encaps < ENCAPS_SSLv2 || encaps > COMPAT_ENCAPS_TLSv13))
  exit(1, pp_info["l4_proto"] + " port " + port + " uses an unsupported encapsulation method.");

# For debugging
fn = "ssl_supported_ciphers.nasl";

# Determine whether this port uses StartTLS.
starttls = get_kb_list("*/" + port + "/starttls");
starttls = (!isnull(starttls) && max_index(keys(starttls)));

ssl_dbg(src:fn,msg:"Testing port "+port+". starttls:"+starttls);

# Choose which transports to test.
if (thorough_tests)
{
  supported = make_list(
    COMPAT_ENCAPS_TLSv13,
    COMPAT_ENCAPS_TLSv12,
    COMPAT_ENCAPS_TLSv11,
    ENCAPS_TLSv1,
    ENCAPS_SSLv3,
    ENCAPS_SSLv2
  );
}
else
{
  if(is_dtls)
    supported = get_kb_list_or_exit("DTLS/Transport/" + port);
  else
    supported = get_kb_list_or_exit("SSL/Transport/" + port);
}

# Determine which ciphers are supported.
supported_ciphers = make_array();
known_ciphers = 0;

#Try all at once eliminating the cipher suite chosen by the server
#until all of the server's cipher suites have been enumerated.
foreach encaps (supported)
{
  ssl_dbg(src:fn,msg:"Testing encaps " + ENCAPS_NAMES[encaps] +
    " on port " + port + ".");

  start_supported_ciphers_size = max_index(keys(supported_ciphers));

  all_ciphers = get_valid_ciphers_for_encaps(encaps:encaps, ciphers:ciphers);

  first_time = TRUE;
  added_at_least_one = NULL;
  ciphers_to_check = all_ciphers;

  # Iterate over each cipher.
  while(first_time || added_at_least_one)
  {
    added_at_least_one = FALSE;

    recs = test_for_ssl_support(ciphers_to_check:ciphers_to_check,
                                encaps:encaps, port:port,
                                known_ciphers:known_ciphers, dtls:is_dtls);
    first_time = FALSE;
    if(isnull(recs))
      continue;

    result = get_received_ciphers(rec:recs, ciphers:ciphers_to_check);
    foreach known_cipher (result)
    {
      ciphers_to_check[known_cipher] = NULL;
      known_ciphers++;
      added_at_least_one = TRUE;
      supported_ciphers[encaps][known_cipher] = TRUE;

      ssl_dbg(src:fn,msg:"Found supported cipher: " + known_cipher + " via " +
        ENCAPS_NAMES[encaps]+" on " + pp_info["l4_proto"] + " port " + port + ".");
    }
  }

  if (max_index(keys(supported_ciphers)) == start_supported_ciphers_size)
  {
    #iterate one by one
    ssl_dbg(src:fn,msg:"The first offer of all ciphers returned " +
      "nothing.  Trying each cipher, one at a time " +
      ENCAPS_NAMES[encaps] + " on " + pp_info["l4_proto"] + " port " + port + ".");

    #We already know that this is SSL and at least one cipher suite is supported, if we get a
    #NULL response on the first try, move over to the legacy strategy.
    foreach cipher(keys(all_ciphers))
    {
      ciphers_to_check = {};
      ciphers_to_check[cipher] = ciphers[cipher];

      recs = test_for_ssl_support(ciphers_to_check:ciphers_to_check,
                                  encaps:encaps, port:port, dtls:is_dtls);
      if(isnull(recs))
        continue;

      result = get_received_ciphers(rec:recs, ciphers:ciphers_to_check);
      foreach known_cipher (result)
      {
        ciphers_to_check[known_cipher] = NULL;
        known_ciphers++;
        supported_ciphers[encaps][known_cipher] = TRUE;

        ssl_dbg(src:fn,msg:"Found supported cipher: " + known_cipher + " via " +
          ENCAPS_NAMES[encaps] + " on " + pp_info["l4_proto"] + " port " + port + ".");
      }
    }
  }
}

supported_ciphers_size = max_index(keys(supported_ciphers));

if (supported_ciphers_size == 0)
  exit(0, pp_info["l4_proto"] + " port " + port + " does not appear to have any ciphers enabled.");

# Stash the list of supported ciphers in the KB for future use.
# Each cipher is match to the corresponding version
# Generate report for each version and its ciphers
foreach var encap (sort(supported))
{
  if (isnull(supported_ciphers[encap])) continue;
  supported_ciphers_per_encap = keys(supported_ciphers[encap]);

  foreach cipher (supported_ciphers_per_encap)
  {
    if(is_dtls)
      set_kb_item(name:"DTLS/Ciphers/" + port, value:cipher);
    else
      set_kb_item(name:"SSL/Ciphers/" + port, value:cipher);
  }

  if(is_dtls)
  {
    if(encaps == COMPAT_ENCAPS_TLSv11)
      ssl_version = "DTLSv10";
    else if(encaps == COMPAT_ENCAPS_TLSv12)
      ssl_version = "DTLSv12";
  }
  else
  {
    if (encap == ENCAPS_SSLv2)      ssl_version = "SSLv2";
    else if (encap == ENCAPS_SSLv3) ssl_version = "SSLv3";
    else if (encap == ENCAPS_TLSv1) ssl_version = "TLSv1";
    else if (encap == COMPAT_ENCAPS_TLSv11) ssl_version = "TLSv11";
    else if (encap == COMPAT_ENCAPS_TLSv12) ssl_version = "TLSv12";
    else if (encap == COMPAT_ENCAPS_TLSv13) ssl_version = "TLSv13";
  }

  version_header = '\nSSL Version : ' + ssl_version;

  raw_report = cipher_report(supported_ciphers_per_encap);
  report = version_header + format_cipher_report(report:raw_report) + report;
}

report = remove_footer(report:report, cipher_array_size:supported_ciphers_size);

# Finish generating the report of supported /iphers.
if (isnull(report))
  exit(1, "cipher_report() returned NULL for port " + port + ".");

report =
  '\nHere is the list of SSL ciphers supported by the remote server :' +
  '\nEach group is reported per SSL Version.' +
  '\n' + report;

if (starttls)
{
  report +=
    '\nNote that this service does not encrypt traffic by default but does' +
    '\nsupport upgrading to an encrypted connection using STARTTLS.' +
    '\n';
}

security_note(port:port, proto:tolower(pp_info["l4_proto"]), extra:report);

