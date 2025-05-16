#TRUSTED 16cacd8369f9888bc44c2ad1879ed712202d7d443e35c9c146a8e29336e36117dcce421f75ab8f587d57fd9868adeaf2e332c1ab12bd94f1cab994e6402af52df8ae87e3b89a4b8e6c7db7d8091140aa849b2a2fa4d707ec20e34985bcad2c7d1c84d82c9e1ed91cf438b17a4dc16035532c14b4fa3bb03f85880f1834dd76731cfad38450e82f78303d017574d3cc08a948d6d632362ccad0a5d9912ffb16a85ae0b5bf3cbe9fef261e40a4247085fa28914bb6d03d1904c69164e03130010a75e5d56905f69edce663dbb9ff8c716ba2eb19f629e4569632abc32bc6ae9de231dc7edc86a154a72d05870d1ebdaf5d1677f5b07b5dae68b7ffa78b85f03365ee209c6a63de6b1bef7f711f65ce7295f63b3dfa1cb4bc69f7c0b686e77bd755478e49fcb89c5658996785668c288fb392a9f4bb164311e7dfef319780b90b188242856960752ac4bf82544c688a74b92d2df51eb560638472a8bc5802306bb15440583a8031428468d1b1b147bffadaade3af8d56c90fa7062597cda2c8801d1d4bce1a890faac60536f556288ad0ddd7cc7f03f97e0a631f06a974dd26c502a09a114634f2fc9804c5ab965953efae8b0b717271d3d6d173856c17508616bb6628a147fbb011c4818c9d2c6546421b7f3780d32cd221319f06a1ff4b8c2a1455afd72a64c77bca94ffd9b20fa4d58e7ef81e8f548be2408012bbd030415d02
#TRUST-RSA-SHA256 75ce700d820b79774d594c0c334f7cee55e61325d5faff0358b3df9daf3ac3052605fd67f2c5d15430a6cd7205fdc619bb5938e681b3827f17adc866f5253fe044cc8da4fe07d7c1365bc37af5599dd1953d68a1a1ab6326cf8b89ecf940bb727abb52844fa2e7eaca003889753ca80d47842303745ba11faa1a1edc569f0d4ef2d8695284d340b75dc424c3df9eace13e0d5c78c7e051a471a02e43a07b00cff1d3a667c678694c99f3bf8a5581ee6b9a6e2fcd303c5f49e5314cd8aa666d47d84dfed62c9422d6bb06a430817fb8bb407abe66f1f9cfe516a9fc254386004fd893563a7506c4c62addf88d2e5222be3a26d8af836530969cd48b9a87706025f2b0a064fcb4f657d2d807d49b98de8305d00b6a197581f01d21b750a7ecddd2bde51819cea7ed9879a6762649ae4b3f15eb60d3e816a80dcaede1f589fa06afe259e86ac661b7c7576762da10054f0a548a14a96af1e098dd287ab285fdc0c38253e8b1661b76c74cdca8e792a36fe9690b41e4aac876da83b665a41205b1988c916f9bafbc00c9eb417d69103fc8793013e80bfd782210530440ad88c859dbee3c1da51b956201512c9fe2649b8d517c90bb1450c3871446ff36f56efbaecd85f22e047a6d02d581dd9be11942ac983cddf410f5a4ab46c925e119224fa19d26320562c57548528ba478f3dcc3ecd5f6a501f2f296603fadba96afef449c45
#
#  (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(27841);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/08");

  script_cve_id("CVE-2007-5846");
  script_bugtraq_id(26378);

  script_name(english:"SNMP GETBULK Large max-repetitions Remote DoS");
  script_summary(english:"Sends a GETBULK request with large value for max-repetitions");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote SNMP daemon is susceptible to a denial of service attack.");
  script_set_attribute(attribute:"description", value:
"It is possible to disable the remote SNMP daemon by sending a GETBULK
request with a large value for 'max-repetitions'.  A remote attacker
may be able to leverage this issue to cause the daemon to consume
excessive memory and CPU on the affected system while it tries
unsuccessfully to process the request, thereby denying service to
legitimate users.");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5aef7a73");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?355da3c5");
  script_set_attribute(attribute:"solution", value:
"Disable the SNMP service on the remote host if you do not use it. 
Otherwise, upgrade to version 5.4.1 or later if using Net-SNMP.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2007-5846");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/05/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();
 
  script_category(ACT_DENIAL);
  script_family(english:"SNMP");
  script_copyright(english:"This script is Copyright (C) 2007-2023 Tenable Network Security, Inc.");

  script_dependencies("snmp_settings.nasl","find_service2.nasl");
  script_require_keys("SNMP/community");

  exit(0);
}


include("global_settings.inc");
include("snmp_func.inc");
include("misc_func.inc");
include("audit.inc");


community = get_kb_item_or_exit("SNMP/community");


port = get_kb_item("SNMP/port");
if (!port) port = 161;
if (! get_udp_port_state(port)) audit(AUDIT_PORT_CLOSED, port, "UDP");

soc = open_sock_udp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port, "UDP");


# Make sure a request for sysDesc works.
oid = "1.3.6.1.2.1.1.1.0";
desc = snmp_request(socket:soc, community:community, oid:oid);
if (isnull(desc)) audit(AUDIT_RESP_NOT, port, "an SNMP sysDesc request", "UDP");

# Ignore Microsoft's SNMP service.
#
# nb: these strings are from os_fingerprint_snmp.nasl
if (
  desc =~ "Hardware:.*Software: Windows " ||
  desc == "Microsoft Corp. Windows 98." ||
  desc =~ "^Microsoft Windows CE Version"
) exit (0, "The SNMP server listening on UDP port "+port+" is from Microsoft.");

res = snmp_get_bulk_request(
  socket:soc,
  community:community,
  oid:oid,
  non_repeaters:0,
  max_repetitions:240000
);

if (isnull(res) || report_paranoia > 1)
{
  # There's a problem if our original request no longer works.
  desc = snmp_request(socket:soc, community:community, oid:oid);
  if (isnull(desc))
  {
    security_hole(port:port, protocol:"udp");
    exit(0);
  }
}
audit(AUDIT_LISTEN_NOT_VULN, "SNMP server", port, "(unknown version)", "UDP"); 
