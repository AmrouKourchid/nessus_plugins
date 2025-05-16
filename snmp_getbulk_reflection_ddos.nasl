#TRUSTED 59dcc439b81290b86773805a66d5ccd29ae9fb73f787cf9c713fa8516763140abe6d164b10fab479d2e88bf1ba034bfcb1d769852d8f18484342bb43c28f56862f5c5d0eca994153274841331859b5ea66f88650afd105ad3549e924db2036d362a4130ac19428ed4720e68f3a5f359bcc948e9b784dac751a4e9e025d5147b7c1b102829196232e3ecebf832d3c01eeeb5f8a5554ad902482369c9a4a522c312fab441ae74b8a4ae17e56a3e3b6dbcd303c96d21b327c1a373d3a714e6ae809f11084606b057231fccf38bef61d0d0afacd74381c46b839495563aab83b5c8f84ac03cf97a757c31ba853a968cc1878bcb9c3fd4c0d44601bb7a3c14e70ca2b66c6810dde524fd8bca071b50a8f45f330c2035c79f62f07d2898478951a0c2863f29c494b4ef0ab34d94722c83f7f57f9f2bc176d9bef3f689603cc1976d1620bed7403034f39481c9e01e07a7a85beca5a5dd3a0f0047f207b077c760ff6c9fae6a87ef6001aa04e31e2315de5b3aa66f7850af268d91e24119c8c8a0664f156ab7c881baba6feb2e44e9ce442f628f9455107bf053655ab7281bcd570a3a7f95f2b9b4af5df56a042a80193004b81699a3c42d4ab0f197dd7e1c17d8d979cb053bf68e8a541ae295049004b349fead983ab640dd17e40f285577bfa288d3243dc127587073a7cdebf6288d7a0cc012237c5a27a4a288c089cab6bbccde1cd
#TRUST-RSA-SHA256 5d93848b25f9756be641512189f9b7e047acd5f44ebd05438a4e9c64e4da6e052202b6132a212252887afd2f8c61ade4d6a24094f8f6c58327c28d01a634ef40cc191a29338083e6b044fbb782db1c8df670139cad4c467b01c5e31192266920a95782143b2d42944cf8c34b80db6670d18f7eed7ff9e10d4da2570800255de177d2cf4c30e54cfb310d985b044ea9b0c7e020cf60eb038241a4ca02defa31fef8ab2c29c72a4ff399ea169e5acc9ba27de95af8e2980ca6679cc6369d5b68cffefdf5d4cdc615ad326d998463b3e70f3889fd7bda2e31c26869b59174e76f1fdc674931b95e7e2b7187bf8fba8cd28de501a6427e586346dd954d477bf062de5a2354f2a8b5c4c835a8f75b02e460782ee622885581c46401b5081fc85951b0386fd9e8a48effc5e37ec2e0261adfdcded898209060f60d33c33a5417171aabf20644aab78185bbcf648109775619e9c355cd5b04a6938790d21c30d5a795a1acfcfcc623a73b07615b0c0eeada7004a51a471ea1d99fab9a7361f8a25900ba3cff7fa2267e5d2931e7f7333a3bc4ba6f35a72775094b248ce3bd5c65640d5fce5311e55904d6ece28de18ce0381812b004698aa13025729e7aed2663f6955bc2dee1721040f1dcd6520ece064b7f7885356920f6800dfe3d9f63a011c3a6cfe26b68c0a8fa6a26fd52b4e07280774f2b807ce8fb544792d3b36eda4f17ff9c
#
#  (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76474);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/08");
  script_cve_id("CVE-2008-4309");


  script_name(english:"SNMP 'GETBULK' Reflection DDoS");
  script_summary(english:"Sends a 'GETBULK' request with a larger than normal value for max-repetitions.");

  script_set_attribute(attribute:"synopsis", value:
"The remote SNMP daemon is affected by a vulnerability that allows a
reflected distributed denial of service attack.");
  script_set_attribute(attribute:"description", value:
"The remote SNMP daemon is responding with a large amount of data to a
'GETBULK' request with a larger than normal value for
'max-repetitions'. A remote attacker can use this SNMP server to
conduct a reflected distributed denial of service attack on an
arbitrary remote host.");
  # http://www.darkreading.com/attacks-breaches/snmp-ddos-attacks-spike/d/d-id/1269149
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8b551b5c");
  script_set_attribute(attribute:"solution", value:
"Disable the SNMP service on the remote host if you do not use it.
Otherwise, restrict and monitor access to this service, and consider
changing the default 'public' community string.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2008-4309");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/11");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"SNMP");
  script_copyright(english:"This script is Copyright (C) 2014-2023 Tenable Network Security, Inc.");

  script_dependencies("snmp_settings.nasl","find_service2.nasl");
  script_require_keys("SNMP/community");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("snmp_func.inc");
include("misc_func.inc");

community = get_kb_item_or_exit("SNMP/community");
timeout = 4;

port = get_kb_item("SNMP/port");
if (!port) port = 161;
if (!get_udp_port_state(port)) audit(AUDIT_PORT_CLOSED, port, "UDP");

soc = open_sock_udp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port, "udp");

# Make sure a request for sysDesc works.
oid = "1.3.6.1.2.1.1.1.0";
desc = snmp_request(socket:soc, community:community, oid:oid);
if (isnull(desc)) audit(AUDIT_NOT_LISTEN, "SNMP", port, "UDP");

res = snmp_get_bulk_request(
  socket:soc,
  community:community,
  oid:oid,
  non_repeaters:0,
  max_repetitions:2250
);

# 42 is the size of a standard SNMPv2 request
send_len = 42;
if (typeof(res) == "array")
  recv_len = res[3];
else
  recv_len = strlen(res);

# if we get back at least 5x what we send out
if (!isnull(res) && recv_len > (send_len * 5))
{
  if (report_verbosity >  0)
  {
    report =
      '\n' + 'Nessus was able to determine the SNMP service can be abused in an SNMP' +
      '\n' + 'Reflection DDoS attack :' +
      '\n' +
      '\n' + '  Request size  (bytes) : ' + send_len +
      '\n' + '  Response size (bytes) : ' + recv_len +
      '\n';
    security_warning(port:port, protocol:"udp", extra:report);
  }
  else security_warning(port:port, protocol:"udp");
}
else audit(AUDIT_LISTEN_NOT_VULN, "SNMP", port, "", "UDP");

