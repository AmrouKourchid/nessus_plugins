#TRUSTED 9e14fe466035871c3538f9093846c750ffe0bcc7136cac57b9c436b027218e6db87538c89f3fc8971d391dc9f2f878f168afa2f14f6fbaa8764b5082d04bc27597dde7cab49f85bddfca5ccde72bcb615dedecfdb859e898e32a50729c07ccba4d3aaf6d8645a5a82b459c86b2124cb728a3faf3e50366e969409bce78bb7c16b17abea706e775231173e6d321240e2d36531c2d25b6ed79002fd14e6f8d789557a2ec0bfc055e7f6c79f55fbb2158ef117607ce94b1bc69c07e1274699b1c7a05d7d13d1a4b5f304657c12a36240deab13c778ce72aeab01553bbb3b3fe3f749a02b4fe8788bb1663dbaafda4ac8f4aa6b9922aa1026f57e2054498c28a9de4bd78b0cc5033c4f968d29c674f12a4777c600d0335954db4cc898975f0ce1f5c0f457c0a93b4b7e812bc45e73ee04e3a13ddbeb3079f0483d60f25ac0cf420971d7f5df641d05faef3f489928021764ff6bc94aaa2bdcc74e50230496c0ef0ebafc352e2fddfe9c94eaea3a5f5b66d28bdd7a53439c603d68123821ed34855a3ed256d5c7b7fe737f91af6b0d5636f900ea17d038d52eb7c61491bc7b4a89afa257400e62b271a74b332a39e03581d342801cd5c8df0f3c469e13d7debb3e00c37e946b5a2fe596c74eb601253b140a8fc5733e227a292bf8759e3f9fbbd9d33aa6119d8e997f995eb04cb7f331e36a4631c0988c533843129e2414025a9483f
#TRUST-RSA-SHA256 3865f133431d0920ec683a5ea0bba925f740b1ac89209206b0e829032c97cd276c950f6649b083d2cf43d671cef3e865fa85a984d8dd6fc48c87c4bc76ffb0e850effc4a50a5ed9302b0d03ed0092b050d420a39543ce19b97d6fac306abda2013c495c648cf8e5d9ea812efcc68e2fd7ffa0ad2fc2b882cd17dffad235419cb6f1ed717468135c5848a799887568b3dd8aa2366a90f40f80914be1eb410abbdcd33a13a88de82404537a11954fe42f4a6bf5b3818745a12361df8fe0522cc7c29ce2b103bad468014d9766f72d399de0f44eea1072ef091684cde18c2ccfa55052f3c73a8a94aa38720566d397abc5e178388ce73096bc5ce774a92535b785e36cc00d7f7d50f669b61db68b2cf27b5996ee54ad171309e4b5c4f3afaf716cce9dc6fc4718b400323fb038e59cf573962d17702faca41b5c8099162eaa9eb5688e55db3fe94e55c12471620ad6220623ed286bd5c0170d85f2c283a186446fdf4c7c0b488897efe9b3fb7ed8145a1166fa4021b58a91e929f60ac4c3f2cd89f3f4d2a48a28ba6c4c0d513390662e4b56220573d17dce2ca17de74359dfc27f0054a4f86ce3dfce7ea5cdaea67d8f7d1855de64e828431db8c38dcf3e425fec4ab77d1f696c87950de965ce86580dd429b185472d4cfbb2b91a57cc3c13c895e370d0dbbe3dccd0bef65ac8d34bf7569e25e4fbbaaf366c7427867c9d3930e19
#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
	script_id(10548);
	script_version("1.33");
	script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/08");

	script_cve_id ("CVE-1999-0499");

	script_name(english:"Microsoft Windows LAN Manager SNMP LanMan Shares Disclosure");

	script_set_attribute(attribute:"synopsis", value:
	"The list of LanMan shares of the remote host can be obtained via SNMP." );
	script_set_attribute(attribute:"description", value:
	"It is possible to obtain the list of LanMan shares on the remote host
	by sending SNMP requests with the OID 1.3.6.1.4.1.77.1.2.27.1.1. 

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

	script_summary(english:"Enumerates shares via SNMP");
	script_category(ACT_GATHER_INFO);
	script_copyright(english:"This script is Copyright (C) 2005-2023 Tenable Network Security, Inc.");
	script_family(english:"SNMP");
	script_dependencies("snmp_settings.nasl", "find_service2.nasl");
	script_require_keys("SNMP/community");
	exit(0);
}

include ("snmp_func.inc");
include ("misc_func.inc");

community = get_kb_item("SNMP/community");
if(!community)exit(0);

port = get_kb_item("SNMP/port");
if(!port)port = 161;
if (! get_udp_port_state(port)) exit(0, "UDP port "+port+" is not open.");

soc = open_sock_udp(port);
if (!soc)
  exit (0);

shares = scan_snmp_string (socket:soc, community:community, oid:"1.3.6.1.4.1.77.1.2.27.1.1");

if(strlen(shares))
{
 security_warning(port:port, extra:shares, protocol:"udp");
}
