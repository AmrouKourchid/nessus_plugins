#TRUSTED a046e2edefed026ce4427240065367653dd2d5b0ad8157590277267bc1647d3897da0370a3da87f5756d56c8dd7892d7835f23921e81c40d4b3a126eb244e320ca2f3786bec197e1077f70ef798e983ea7e24501f057b96b9961de3f09b6e7cb55b83d61b53ca52987affc3087ad21b67b8580e110fa2bd26c6ee476a4237619149c5ec5879cf23642bcbbb390919635b89447e7fed4106b9529c9ae4f3d2d4da5cdd4ecd7d21b33631f1dd0524127e99951398a98977b0e3577e4ebf8ddca2db300d0e19f14dabad96ebaebec26b1f36c5d827064553969d7d74832213dcbc747c55d400c6ea806ca517d0ecc575a515197b506022be3ab3f6ce793f9e18b5fd3437c8c07bc113056c10296b6afe8a04bb77bae56ada5bc8597f9bc7be30325bd44a85f830e7756060f63c7e1773b996b3488c30605f586e6248c8a57c70c4ca7726ffcf48695c68ff23b8b29ee95ca005a5462bffd6b93071e038caa35aac122ed6a03901f50da938030c0559a3d77581d60bb1f37c61c312f21ddb3ed9a6c8724d091e456542a8a6bf515dcc0aac3744d2fdb4d7f6a7c7634c9a6d9844e64aa47fc079acb60be65cc6d05e5a238bfca958400c15b8c27e4c042ad1ab51c8e8f20dc0f4728ce749224e956fb36e81c1c929ec605965449c090de5508424ca2a64128604636381796de34a6fa84e0af702a02edf5635f2e180126f0ebd354d2
#TRUST-RSA-SHA256 812034a64c71051c3dbf8ead5b8c02119e8986a3bf4095bcbb560c03c6c4e5b5d551f7481715987b4de4d8954f55338a0b1663cf62288c4405f024b496a1c44de2958d062e92c6f69d3b29d8fdae85c83c249e25b467a08745bf9890031b4cef8518041215d9b5de29820ba3e6a575aa561d280544890ed6fbc39a9aa2acf981a4be28d84ae3a744908b51ebcff4a417523910496447201ebbcf3dff78e77120d05f45efa3b30cc5bd72cfa53418ad1867cbd8f1bcf55273aa36b2bc271d46c7ef20cfa48e024969ff8977020800db935492556a238539b2b0ba5dba63dc79956cb6e0b8e931da342d05c7c01086af7cd321ab297a4a7c432655febd3c11fe429eed1ad6fc15e27efd50f960cd1fa9d3626599188ed5bb9852d1bfe43a4fd2c3bed46af1702ebbf41900bda7a6364ba3571375de642510e5f160c587e64a32f1c0db263053e231c61e7a562874fa9099fe0d2adae994806e8b5b439a2565f815958c9cde4e8373ccd4ec4438854980b0062d46f605689e1b12ae6a753b868b438b4ae6ec89bf1aaa51c0e49854386137b92b237718e5068a78fd37b25bcd4d6c7ca6eeeb20d6cd5bf412d9b61d23b86b5fe5f82db568185be52ba266029cb0755c14e87363e70c54c5295b727f30f9592a39432e49c436a0d0bbc290cbd317bcb520c56e308ee2ef0a689c4a381ad3b2b8f736448611389392d2701782238238
#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(19763);
 script_version("1.21");
 script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/08");
 
 script_name(english:"SNMP Query Installed Software Disclosure");
 
 script_set_attribute(attribute:"synopsis", value:
"The list of software installed on the remote host can be obtained via
SNMP." );
 script_set_attribute(attribute:"description", value:
"It is possible to obtain the list of installed software on the remote
host by sending SNMP requests with the OID 1.3.6.1.2.1.25.6.3.1.2

An attacker may use this information to gain more knowledge about the
target host." );
 script_set_attribute(attribute:"solution", value:
"Disable the SNMP service on the remote host if you do not use it, or
filter incoming UDP packets going to this port." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/09/20");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"Enumerates software via SNMP");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2023 Tenable Network Security, Inc.");
 script_family(english:"SNMP");
 script_dependencies("snmp_settings.nasl", "find_service2.nasl");
 script_require_keys("SNMP/community");
 exit(0);
}

include ("misc_func.inc");
include ("snmp_func.inc");

community = get_kb_item_or_exit("SNMP/community");

port = get_kb_item("SNMP/port");
if(!port)port = 161;
if (! get_udp_port_state(port)) exit(0, "UDP port "+port+" is not open.");

soc = open_sock_udp(port);
if (!soc) exit (1, "Could not open socket to UDP port "+port+".");

soft = scan_snmp_string (socket:soc, community:community, oid:"1.3.6.1.2.1.25.6.3.1.2");

if(strlen(soft))
{
 report = '\n' + soft;
 set_kb_item(name: "SNMP/hrSWInstalledName", value: soft);
 security_note(port:port, extra:report, protocol:"udp");
}
