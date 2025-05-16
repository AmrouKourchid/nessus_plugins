#TRUSTED 544d826c7d57a1304baad1d261a9850f7269924b38deb12ee0289e0a47a219aa198a382059d06332612f7722717f76b5e9a37606e53253ba3097da6e1cbe4eb96b06a7228a756c8bdf87a287b17bb404cbdb6ed1fe0e66e68b85ff53ac586c01104a01512673c91769d6641b1bbe11d6b689d12d21963786186810f3825819b35b4cba6187eee32e0e188db2eab41d839bb72dffc91ec9c6f2507955f404deebecb9c31857aa093a1ec0328fe18048ba6205fef4aa06faf6690381e7b36ec295be4c19297b46998bf38e5586f1ece77a2084c96b094ba388365d52e1c1b440c12c65f6ea785cf22432198cff69bfed992bbced8c0e71bae1cbe25bd4fee445afc2d7902d0e6241f75b65022f37aa5a19b7d9b721eed41628ebac34ebc32da4e74209bccac392825af34301dddef52fc9333d9a28ecf685459c3d25e73299b9585acff7650d004ebd75f7a0accb91b5c8a5466f5b87f2cb6f3f68e1e0abbcf6c7713bf17396d2a7d0aa4eac54a8127efa9bd4d3c4185ce6e254a66a8be4fba6ddb809ce97d6323ef5ea85fbee32fc0e03003b783fbe1446497c7d3d15f5e7c3ff7a623ca5f8456188e3b8fc718f7efa9115190431c7ea557e332a712916edcdc5c368f094c536d485609259eee1d3296ff5c20aa9f6ff254fbd6c113679c140a47f325c93eb5247f9617ecebd47e61f9e46357d1db8cc48573d8954104b320ec8
#TRUST-RSA-SHA256 46806fb42486dc758dc653e143c78b7045d77eb3093503dd3da5a82181d05fc376d4634323d787b10515d4622558b830b9390dd27e432a4fa2d975425cf7ac78505e2b87abb923fdb14d146e8ab93299792f8f1369c683178b90e3fe72979a31d42b792bc60d62753be3ae4952d15a109ad0850ed710e81d801647f3c82ec6a6e3b7a3488923a62517e17db78aa4a33596a744dafb86b7728aa9687ad0c8d5d2a5a5522bc1d73b274893eabfce8171b90ddc89f2047741e9bd254698ec16d2d1d39ab5e5085be63ad62fd15e37d1127d148a4c48dce23276f06f3c0651f5ca0ab4c45a2135b34473f553344acb320bd6bee988d37aaa74b6b6f11a9be7a2c35edd138eefce1319ef56bf88c0a5e60f7a8844c0304b539260b65db3ec9229bab97c6b90aa7e0c9f025c393dea8310cc54065d6393dfe59a5394113951476fbb5feb854e9117d02073292ac44db9607d38a41b11d4d7ec30c52b919900003a1f9df4d619434ecde2e97ad32cfb82070c101747d4ed58c498c03e21a32daa6bf21d99b91e2cce3e176fea554652c522b92315de0c9c5d56ef7692f206dee567e5ae5b69d0bc2875fc8fa214c730e48e42147e07ded7f571621b9ea17df2efe1c0f7051f2ebb7f93b8931f64f72e9ce5e41423f777e0a474120f7e5413691d22a20f402daef34c53f4406fbfa0616bc1a75f83f804241d4e22209bf8b341cc2b8108
#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10688);
 script_version("1.32");
 script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/08");

 script_cve_id("CVE-2004-1775");
 script_bugtraq_id(5030);

 script_name(english:"Cisco CatOS VACM read-write Community String Device Configuration Manipulation");
 
 script_set_attribute(attribute:"synopsis", value:
"The SNMP private community strings can be retrieved using SNMP." );
 script_set_attribute(attribute:"description", value:
"It is possible to obtain the remote private community strings using
the View-Based Access Control MIB (VACM) of the remote Cisco router. 
An attacker may use this flaw to gain read/write SNMP access on this
router.

Note that a value in this table does not necessarily mean that an
instance with the value exists in table vacmAccessTable.  The SNMP
private community string(s) returned may only allow read access." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?59d222dd" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?df9dee8f" );
 script_set_attribute(attribute:"solution", value:
"Disable the SNMP service on the remote host if you do not use it, or
filter incoming UDP packets going to this port or install Cisco patch." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2004-1775");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_publication_date", value: "2001/06/15");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"Enumerates communities via SNMP");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2001-2023 Tenable Network Security, Inc.");
 script_family(english:"SNMP");
 script_dependencies("snmp_settings.nasl","snmp_sysDesc.nasl");
 script_require_keys("SNMP/community");
 exit(0);
}

#

include("global_settings.inc");
include("misc_func.inc");
include("snmp_func.inc");

oid = get_kb_item_or_exit("SNMP/OID");

# Only checks for cisco, else it could be FP
if (!is_valid_snmp_product(manufacturer:"1.3.6.1.4.1.9.1", oid:oid))
  exit (0, "The host does not appear to be a Cisco device.");

community = get_kb_item_or_exit("SNMP/community");

port = get_kb_item("SNMP/port");
if(!port)port = 161;

if (! get_udp_port_state(port)) exit(0, "UDP port "+port+" is not open.");
soc = open_sock_udp(port);
if (!soc)
  exit (0, "Failed to open a socket on UDP port "+port+".");

comms = scan_snmp_string (socket:soc, community:community, oid:"1.3.6.1.6.3.16.1.2.1.3");

if(strlen(comms))
{
 security_hole(port:port, extra: comms, protocol:"udp");
 exit(0);
}
else exit(0, "The host is not affected.");
