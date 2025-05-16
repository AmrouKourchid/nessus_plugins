#TRUSTED 2b351e17e85714e51e9b7cae797019b7f04dbb932158da3bce20a080dffefb3bb3daf933ce1396c2e67679bb52e5a2393132db8bf67507e09412a15cef02120da7de7cc876697f1ef72b59ce5aea47f2179117758533b83cbaf3a0ca1063cf8179732e450a8d51011e1edf33b90d4e57a61759eab16ea8fb027e1f25e158a74652e6eba98aee1637e02ce2abaccbe7bcdc14fdaab4fb997cb6682ea07462311a8a55a9587370726e5ff990270eba43aedac9a5bd307ca7b34215950a0677c402c44ce3cb6138aae72f851cd80acb1200ba55ceba8115e79066d78af51646d448626e2723e41fd6459b5db45c521b06d82bf046a7169b6de01d8cb5a7d7e1a5f67aa277015f931ba974cd483c3ddaeb1bc6531931539dd3cd4d6b9761fcacbe508d0c52a42fcc2090d95e0d268d9db34bf6a92ef1d4b41f7a81ce7be2405a5ef86247858b7c360d62914d1936cc40de5e3423204b2ae58e736d0c2e74414110025506d354370a18c8989bbd376d2ce2287936d3cd46312cd3a4ee1a0daa7e870de51f4a060afde41eaa4875f05185f6a8dbdeeab397bde57612d5a97c77a19b9cb7f55eb6ffe068ab3344e4e1f8e3cadb86336edb197b985850fea3039f19799aa07dab8d71bec8e09f0296bb97f9f1887f8c385867e2779f2b3e01d1ea11d5004fb99330b34f64f79aa56d2f63d6cd1b5d2c6e9a36e4139812e6ae9a7220f543
#TRUST-RSA-SHA256 53a8a706447114c1863dca2225650c9bce0b293a171f93943c052e3b1581aa59891d4c9882d16a99e71d6a52270b1e3b7cc760344171726afe98e04574dc07a38995d3106ccf259521eade468b5e5a3f1ad79e6af611f9a89619ff51b5cf8ad385bef9f01c790a10a5921375ca58e43533f9523746718612b3f62fa346e1ccfd036a5e8d7bacffe8647d39a7f2b3b912749dc179da4adbe76e4c145d36016b212728c058b4934a027ae698f8495376440e4cb1b37333797473dc7ef35b168789f51f173cd654a9644d7b879b4f2e0eedb2c47e22778e9de040740d1b413f39cb702f316a087cc35f1d67c351bc3d9443e056ac35d4e18503b23ae05944b6f589df66cc0c5600299cb3228095ae6b0d66aa1784d7334abd9369cc18d1a4189799cc46bb37035a9aa7ce86940e259b1a71e517ad9bf6bb0a43b9a1cb9bbf86099060288ec2c2eb436a6b617365838290a1c76645e3144f957941ee4f576259453a13a7ef2776aa39cf0942fd0843bf1a9564b8e4e6ac3b6efaaa13345d013466e741923d6eb8cbbe52fdf54fef872bcaeda031b18dbceb9dbbdf202d20f0a34c8bf9a508a61e5765dab5fac09a121b6e56f124862410dfea9478cb3c548da8e95d97ad5e21c8ad19b7e4511b0a9c701a54c7af53136d347fb718fb25232455f2df3d29c141df52d05395b549171f56c091edf2557cba6e2a6073f0d9d1cd5cc0be
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(11317);
  script_version("1.33");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/02");

  script_cve_id("CVE-2002-1048");
  script_bugtraq_id(5331, 7001);

  script_name(english:"HP JetDirect Device SNMP Request Cleartext Admin Credential Disclosure");

  script_set_attribute(attribute:"synopsis", value:
"The administrative password of the remote HP JetDirect printer can be obtained
using SNMP.");
  script_set_attribute(attribute:"description", value:
"It is possible to obtain the password of the remote HP JetDirect
web server by sending SNMP requests.

An attacker may use this information to gain administrative access
to the remote printer.");
  script_set_attribute(attribute:"solution", value:
"Disable the SNMP service on the remote host if you do not use it,
or filter incoming UDP packets going to this port.

http://www.securityfocus.com/archive/1/313714/2003-03-01/2003-03-07/0");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2002-1048");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2002/07/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2003/03/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SNMP");

  script_copyright(english:"This script is Copyright (C) 2003-2025 Tenable Network Security, Inc.");

  script_dependencies("snmp_sysDesc.nasl");
  script_require_keys("SNMP/OID", "SNMP/community");

  exit(0);
}

include ("snmp_func.inc");
include ("misc_func.inc");


oid = get_kb_item("SNMP/OID");
if (!oid)
  exit (0);

# exit if not HP
if (!is_valid_snmp_product(manufacturer:"1.3.6.1.4.1.11", oid:oid))
  exit (0);


community = get_kb_item("SNMP/community");
if(!community)exit(0);

port = get_kb_item("SNMP/port");
if(!port)port = 161;
if (! get_udp_port_state(port)) exit(0, "UDP port "+port+" is not open.");

soc = open_sock_udp(port);
if (!soc)
  exit (0);

pass = snmp_request_next (socket:soc, community:community, oid:"1.3.6.1.4.1.11.2.3.9.1.1.13");
if (isnull(pass) || (pass[0] != "1.3.6.1.4.1.11.2.3.9.1.1.13.0"))
  exit (0);

hexpass = hexstr(pass[1]);
if (hexpass == "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000") exit(0);

if (strlen(pass[1]) <= 0 || pass[1] =~ "^ *$" )
  exit(0);
else
  password = 'Remote printer password is : ' + pass[1];

security_hole(port:port, extra: password, protocol:"udp");
