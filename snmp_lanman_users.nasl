#TRUSTED 873cc2985ee5f5efa571c4862ed75327d5705c67ce6e6e87c52de2c7e009b0f0dfd134c33aa82b0f17c9e83b3dc01fbb8733fc6b3a6c4dfde6c80454fc739a5bf9d38ec957f06984fbf58dd9257e2ad9e43bd2b4b63f70ce50f191b3ea3a0c6ddaefe5df36e91f05760e02e9a3b8ca97f4188c1e801755ae8d8363fa526c185d44d7f8288ecd6d457eeccc50300be387a056ffb0b05e95f499b058cd83222d2bd9ae6ea1dc52552aaa9a65cdcfea4af0bc23cccbe061fa315dc354c650a6315d58775c08fe2e9bb050d73d4dfdecb2384300d5d242e3557e0e5a2c3776c198174da59d1ac71b673cfcbfa3a4ae9ddf6cab2fdf5ae78c8055423fc83bee4002eb9f24165f059ff1621d2fb8bb69d697bc70a3f808ee8b41830d5f452dc69245e4006e03e7923b37267b5b6abc46c6b119b3593aa929fae0d4cbb0def20dac5809c4eb6e403ead4c0efb10fe67c26b3380cb37ae3b5e1693e18425c89446bb0648935e6e9c5e4691c3ebf934920733bc64ae25c0e7468bb0df6f88142703754a31f209d369cfbbe720dbd4d7db602b8573e41904c2576963ba9d6e47b172b158359de8d4d22524e811d0ef5299afbb0248e2203da283d29d61cfbe24e5080d8530ff3b56740f553cf1c197afe963675c0b1814bbb75b69c6e8af68703a1631860ca68ce73025a56a406beee4c3a248ffed1628132c985687ff9f6dac145aac6546
#TRUST-RSA-SHA256 a61aec6e195c80842323e86e97298d72f09963eeae940ab86dca2055422a4c15bedcbe050f059eebca11c39a569948eff4a108dcab64e5ee5a15fd0c56f3e6f7bc7bb6da3389e34e2aaa9adecad1e935bcdc7be9bc23e102167746b34f2913d3424deadba8f52a44bcfc218697855135b53c3de9dea6d8012b18b9f1a669b623580a7befd83fa0414bdcdd4a81f58f4b4ed78bbbc15cac72021ed454c1d74ef2a0f2804aab577bdc47201bfa5b20ac6dcc4bb976e88107dd49bf2744c8491b935d0439637ae4e056633e1bb0d452c45392847f9fe61e2ed797f5010cf4bcc83f90f2e71350cf2798561400f5e03267008a3d5afa7443da2eb343205649174612552b0128550dbc08d1e4aecc270a0cc1b3162d9e3940d85e72eb8d117e14580a9f2f970f44d1140a0a14eba43c50e3e45d46c956c90f603bbee82e9f7d709b910949a2f222df4d51f43795095178f14809bfd1a146bbc56c4c7982fc4b1d71d4d0e985c7e293b7d8137a43c9f6e5845375603300384b9552078efead013f59548ca01b0fd6fc165e5f6516f8c1bc4e2e1d49178d06c506e1b3670d48885cea844af4993222149520973c5ef81971d28870efda1455f1063e450fb6fef2b5f5101156a0cae294b2733e6f6e05de941f6bb6ef9e40c634338b0bc612adf90301e98cf864188eb70440228991eb45f357990b04c3de03c2e96bea9d3ee5ff0de61d
#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
	script_id(10546);
	script_version("1.42");
	script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/08");

	script_cve_id ("CVE-1999-0499");

	script_name(english:"Microsoft Windows LAN Manager SNMP LanMan Users Disclosure");

	script_set_attribute(attribute:"synopsis", value:
	"The list of LanMan users of the remote host can be obtained via SNMP." );
	script_set_attribute(attribute:"description", value:
	"It is possible to obtain the list of LanMan users on the remote host
	by sending SNMP requests with the OID 1.3.6.1.4.1.77.1.2.25.1.1

	An attacker may use this information to gain more knowledge about the
	target host." );
	script_set_attribute(attribute:"solution", value:
	"Disable the SNMP service on the remote host if you do not use it, or
	filter incoming UDP packets going to this port." );
	script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
	script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
	script_set_attribute(attribute:"cvss_score_source", value:"manual");
	script_set_attribute(attribute:"cvss_score_rationale", value:"Tenable score for Information Disclosure");

	script_set_attribute(attribute:"plugin_publication_date", value: "2000/11/10");
	script_set_attribute(attribute:"plugin_type", value:"remote");
	script_end_attributes();

	script_summary(english:"Enumerates users via SNMP");
	script_category(ACT_GATHER_INFO);
	script_copyright(english:"This script is Copyright (C) 2005-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
	script_family(english:"SNMP");
	script_dependencies("snmp_settings.nasl", "find_service2.nasl");
	script_require_keys("SNMP/community");
	exit(0);
}

include ("snmp_func.inc");
include ("misc_func.inc");
include ("data_protection.inc");

community = get_kb_item("SNMP/community");
if(!community)exit(0);

port = get_kb_item("SNMP/port");
if(!port)port = 161;
if (! get_udp_port_state(port)) exit(0, "UDP port "+port+" is not open.");

soc = open_sock_udp(port);
if (!soc)
  exit (0);

users = scan_snmp_string (socket:soc, community:community, oid:"1.3.6.1.4.1.77.1.2.25.1.1");

if(strlen(users))
{
 users = data_protection::sanitize_user_enum(users:users);
 security_warning(port:port, extra: users, protocol:"udp");
}
