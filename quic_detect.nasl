#TRUSTED 3697b13571b6b93664a00c83bff58410689fba57fee5d0a185c40ca600e92c4091d4805edd788ee25b410e5b37787f1d390121984eeaa47f110e92eb473f34f4b3ed830b00d7e584edaf6270bb9b46633d8f14a3535c9811bbd81c385f2178127a16d27f27320fdaa0ea494ff948cd66f5e58d2709b85964e56a92e671ae78d5a3cc267d4c48b7d30c275aae966789fb06e1e5a2f54389ef5c57c922bbaa4b77cc1dd13dd745ba9be99e53d79e02c7a130af14211ef073987d1c5e55f51fe5c557eaf58807672504a1f027c4a3defb13786ceff953282f7b82581d1272e62cfb37dcb1db216811faa1fa368961acd8898c45d09729256166f281662925e5bb596e75dda91cc700aa9a84d0c3f34a9c460c754b532518fad841213875e05cc4b9f833b9879d25da2509772242746506cec67324fd90b52601b881bc07daede68c6e5458b7d6bf4668db0787793f64eefe2cf4d327ce1246c8a3a6035d10c16479d9c7f17b768a81acce69f816bf51c4193177a9979f62897083cc9bd2856d6a1f78df337f90d36bc04e3bae82162d252c338f873be009425a761076cc869e8e06e49046442655a4f5e43878191950a5199c84cdca4da326c2bef82ad577d77401be56121f35e0008e80d830c7a5f1f3d07ea01fc471e5a763a4239fc49adc19ea49d975a232bf50e4d1466d24d3baa9743abdd1b42d1576f12dbef2475b733cf3
#TRUST-RSA-SHA256 3d5618f2edcd653fcb56f831da9e2b0bfa08bee861e09d194849978c76aeed55401e42ccdb7bbc780b2b38d0711c86b025f342beb00833c27007a53652ce0e060504df53b23e40f5015167fa042d52644fee953d41bcb4158f63e8b9fdf79c065b700ef81fe4673ae86c39f7a13ecd4061af4380bb2e8e33952bd775646b6d476a96d7234642fa43e73a1691bcd31d9c6abc34f96a121afabfc221366fbc9db7892d2b3843f8aeb2e1365642d18c3980d0e6a8938fef7daf0c14a31d3ec4d531d1c052de8d7045fdb26dff1ddd30cd3961555a853e5b987b5d2bb110602d7a70d6afed71d1aca8c67298fcfa70412a8db3c69ec59d8167a52e2a8ab6d0bf7ea3bd3667d7527c436a105c6d6a2d40ce03b6fd7cf978a0ef19857f423d30ecc9e24c3028a944e5930cdac07624a4743beadc0474a2a3cb9cf6689d511c190bb84b68821255bc662b5936ac8d927562536b8ba4dc81aa5efe9d704ce99d84524b8347646415f7ccb193254afae8e7ac729820a37028de7d8b80bcc384bd29ca18c2c9eab4cacec7f5eacf77aacff889eb5cf6da7913b5e9f06e8630e10837324a25712328ca3b71cbc6acb82bde8b0058816668f75f4311ed8475d052781f6dee1af91db1a09ed5a024a6acd7d6734620af36f047d34bda529b0154a4e9919716f3d083246564e32512eec11767becbd195d9aaac1d423920913833d431ee9a80cb
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
#

# @PREFERENCES@

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(206982);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/11");

  script_name(english:"QUIC Service Detection");

  script_set_attribute(attribute:"synopsis", value:
"The remote service(s) support the QUIC protocol.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to detect that the remote service supports QUIC by
sending a QUIC initial packet and receiving QUIC handshake messages in reply.");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/11");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("dont_scan_printers.nasl", "dont_scan_ot.nasl", "find_service_dtls.nasl");

  exit(0);
}

include("quic_lib.inc");
include("sets.inc");

if(get_kb_item("global_settings/disable_service_discovery"))
  exit(0, "Service discovery has been disabled.");

var default_quic_ports = [ 80, 443 ];
var testing_pref = get_preference("Test DTLS based services");

var reported = FALSE;
var num_tested = 0;
var quic_ports = [];
var udp_ports = [];
var port;

function report_finding(port)
{
  var quic_suites, cipher;
  var desc = "A QUIC server is running on this port.";

  reported = TRUE;

  replace_kb_item(name:"Services/QUIC/" + port, value:TRUE);
  if(!isnull(testing_pref) && ('All' >< testing_pref || 'Known DTLS ports' >< testing_pref))
  {
    replace_kb_item(name:"Transport/DTLS", value:port);
    replace_kb_item(name:"Transports/UDP/" + port, value:COMPAT_ENCAPS_TLSv13);
    quic_suites = quic::cipher_suites();
    foreach cipher(quic_suites)
      replace_kb_item(name:"DTLS/Ciphers/" + port, value:cipher);
  }
  else
  {
    dbg::detailed_log(lvl:1,
                      src:FUNCTION_NAME,
                      msg:"Service discovery of TLS over UDP has been disabled by scan preference.");
  }

  security_note(port:port, protocol:"udp", extra:desc);
}

dbg::detailed_log(lvl:1, src:SCRIPT_NAME, msg:"Using TLS over UDP scan preference: " + testing_pref);

if(thorough_tests)
{
  var base_key = "Ports/udp/";
  var port_list = get_kb_list(base_key + "*");

  if(!isnull(port_list))
  {
    foreach port (keys(port_list))
    {
      port = port - base_key;
      append_element(var:udp_ports, value:port);
    }
  }

  var p_set = new("collib::set", default_quic_ports, udp_ports);
  quic_ports = p_set.to_list();
}
else
{
  quic_ports = default_quic_ports;
}

var conn, ver, encaps, res, quic_suites, cipher;
foreach port(quic_ports)
{
  num_tested++;
  conn = new quic::connection();
  res = conn.open_connection(port:port);
  conn.disconnect();
  if(dbg::is_error(res))
  {
    dbg::log_error(msg:"An error occurred trying to connect to UDP port: " + serialize(port));
    continue;
  }

  report_finding(port:port);

}

if(!reported)
  exit(0, "Tested " + num_tested + " ports.  No services supporting QUIC were found.");

