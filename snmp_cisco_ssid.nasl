#TRUSTED a02a239ae854110651484903484630dfdfca1bac890c1615f615caea2cc03a913bd4caf1c8a40f297c439491812626dd2a2f1b754e3e66717ad8708079327e13387322450464c0d40108cfaf2f14960d2d373626365d2ead1a1b8517fb0264a7f4a78b744bff6932d5570dfe2e54248354b1061c11c1c9007ef0d772cdefb91a08ab01c2f9a0695643ec8389dabe4c6064e07d8e82b976b64f39cf8858c74e2c5ae053c246542ce42d63728fb6a3ae7e1056333bd7b5ba6796af2b6853f227113a6a6b8b85a5c5250e79f4df8f083f30dab746b2dd1dc781094dba508fb5efe831e1734296556977f82d7dd507d9d5e2273d05d6b319d4e43566c7c0cd58af0a58152b292d637c60165037d950d5f4cd011a48fa52fdf52b929b20350a7ab7dac74d902b591cabc7aabd231db40728b209a014b6a3d81b6de88ba53b13afd895f95a7baf2087e7c34713c3bafcf8677beb19a421019abbaf26e06e21a183ea9b4102dba421f4f28836d894fcfc4a7b4edacaa9ea073b957f220d41e522b6eb8e8a3f42038c134f15e68b94e43e9b6ee46a4268192f97757527eea9d463366aeba8377f13419bc8d34f4fad068e46549b8bce7ee50d54d80579be7f4d2a610742c105d26c27204d0e305ef04f31014e39d200bb56ddc2e2cc1078efe2ad14cf0bf07cc55564ec89f87b4aa867adf2a5923360e7e00ac2b2789b1f2c8ff22610c7
#TRUST-RSA-SHA256 2a5c7d59b5a4561551d0e70464b99ce19cf7729b554c2c4a2761ef20d2a3c6d3387d5fe35a395ad1d220ab64ab508203698a1aba0f68a4d08602cc0b9c16f8c1391981d0e1ae2ac7f6e6a41584531136ae139eb28bc11b314b38057cff019a0a604007448149c81b0f142c3618b7457656235c8a118b1070831a2f52f0ad58a4e56a4708c8bceb995517e3384aa905a779287beb013f833edf9fb179522fb6e543bec800429659b4d19d1483b9e09df6ca4ee6fbd6cf48aefe6d37007c6b5133995fc58dad9ab093b511bdc8d74f898fc2c9daff506874c689d59cf54e1954d608a759b9ee9827d1a7c890c44b391eef3842af748cb6d5cc3db46bb070b636210571a2214d01e51c26051610415d4f24c0c89b2c793ec6119087448ffdf1ff71581202501e6d80cb51bc9eea5bc11c79c2047dc95d18f537dd12ac50a0ae0e98b28ab56eace5917c296f629c310ec81ce0fb5202ce0b64bc76a0879c48486dc3fe591b76beebd292d2aae9e29f3fb6e0a4cc6dd8dbe26ca9a76f8b319153ad0d4cc925fa47e8499da40701e3991bdad9a88b9e3aeb3e036c0881beba15187151b0d3921f1a96c796a9c25dbf18a735abc3581a2366d07aaf5373d2bc276588aded9880fc505ccaf87a845587c7e98287712aa260bbc5b6a604a69254b653c23decbae4631eb9e37bca54f300efc6aa21ace8764ff889fdc14f7542539db4f2c0
#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(43100);
 script_version("1.3");
 script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/08");
 
 script_name(english:"SNMP Query WLAN SSID (Cisco)");
 
 script_set_attribute(attribute:"synopsis", value:
"The SSID of the remote wireless LAN can be obtained via SNMP." );
 script_set_attribute(attribute:"description", value:
"It is possible to obtain the system information about the remote WLAN
by sending SNMP requests with the OID 1.3.6.1.4.1.9.9.512.1.1.1.1.4.1
to the remote Access Point controller. 

An attacker may use this information to gain more knowledge about the
target network." );
 script_set_attribute(attribute:"solution", value:
"Disable the SNMP service on the remote host if you do not use it, or
filter incoming UDP packets going to this port." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value:"2009/12/10" );
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_summary(english:"Enumerates system info via SNMP");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2009-2023 Tenable Network Security, Inc.");

 script_family(english:"SNMP");
 script_dependencies("snmp_settings.nasl", "find_service2.nasl");
 script_require_keys("SNMP/community");
 exit(0);
}


include ("snmp_func.inc");
include ("misc_func.inc");

community = get_kb_item("SNMP/community");
if(!community)exit(1, "The 'SNMP/community' KB item is missing.");

port = get_kb_item("SNMP/port");
if(!port)port = 161;
if (!get_udp_port_state(port)) exit(1, "UDP port "+port+" is not open.");

soc = open_sock_udp(port);
if (!soc)
  exit (1, "Can't open socket to UDP port "+port+".");


ssid = snmp_request (socket:soc, community:community, oid:"1.3.6.1.4.1.9.9.512.1.1.1.1.4.1");
if (! isnull(ssid) )
{
 set_kb_item(name:"SNMP/WLAN/SSID", value:ssid);
 security_note(port:port, proto:"udp", extra:'
The remote host is a wireless access point controller, serving the following
SSID :\n\n' + ssid);
}
