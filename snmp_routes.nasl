#TRUSTED 7779a79031fbba4ba2eaaa2db657d8f8c2011a45a07b852152f9dc7b96c74b3521ec1a54f96dfba459cb65993a7f091cba8d0db08d235aaea548fd78b37db1969ae987fd7a10647914fad7c1a538d27bbffe67bb773dc8378052c4fd5e808508e2b46cb90eabbb53c02787a68ff0d66387983d5490fdf073b5a444a1dc15b3691580bf9c3ff4204770a2c4b3b8782bbcb70725d8c1dd1a2e4475675c135fd4334bf89bef7fedb2b5fe7dfcec15333e161ac715ec758ef0f72e95ef3cd2939f92fbf38506661af5881b92fa2564ae9165310d0306f4ea104045fb83942d97ab4871539e9ef81fbd2dff65173f1d83b6e98d3d01262ff6fd17d4ba664fb96a1e04cc04afef28fb4bbc86fe088752dcb53c8d4583a4495503521feb41a61b0bd128e78bbc861fd3b5b3661d6b7dc6817e595723f239fc31a19162fcf6a604dd6ff85445c590fbc0d88f8f03b64009abe34e48adcef1c0509ed7ad62c073fef80101cafe06d4b5191fe66c86df2157188cd7737335c95e1f189034ac91190c7e62baf3718f469b297fb341afdf8b60bc0a30fc2de751bba294ba0031da4140b47b564abb2eaaa1db4042a3dbbc40e1baf67b0a13368621081e421bda3d6ddc20b12e6fff71ddc9b980bf72c9f5e6abbc426f49b80838f8faaa73caa0d44160667bd5d66599ec706bc2879f3fd969e045afc13d8b9a817d87362c85058cd896ceeb79
#TRUST-RSA-SHA256 1ec351bbb1f03535bc4a7bbc225ff8dbe28917918280b2c9554d0c3840d245d482dbcc9556dfcc4443e18b5602a8ebda3709b912724ea550b92bd50bc17b711efe648aca72650b2c688d0f099b0fe81891ef6c94fa52203364e154306fa132970e1650e65dee6caf7e5122069961d20debd505237841e4e4edee6f01293d4e59e6251e48eef2c0af8db8ef7835c78c657c069aefb5f9c1919ddbcbe88a6d9d53e4660a6203acbe390dd422b01fa9694e6b9af8ffc51d66edc412accbb5a1d145a5ca49567f42f78e3fb2b2ec1d65c60b562a3852231f187ebb992bf287bbdd1974255f8bfdbaa853454268a1bb22db8a5ed826d209c460cb7823c08f1ef1c132fc02e800f0f216adcc349ce13a379f85f7ed72f0a0761b4890ab46db06129baff89efd24671082d0ed720c5e4299723e9112fdc30d05beee978f2ad936e3199b2be51fc4bfaae10beea7e40abdcffbace98a260d21b8d7781cbab3f73cf4c0d01d69e7582a0797725d2c4821904031e6c2e4e4d54166f7c0dad0b1329f16f0248e4cc6cfba3ea5b130091dfbee2ff2cdd6f95f3d58391cc6b49fc1bd86098c22b3737f22975ef1dbc63585c809b70ca13ab234c38677bd020b2a61e02357e249d49630d58fbd42987226e489c1af0d5649a9846e65a1e441bbd63ed6d63f310f5d8395df7a4d58ae318fb0b27ac6de0ebf2988620f4658ec2152464175e3cdb9
#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(34022);
 script_version("1.12");
 script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/08");

 script_name(english: "SNMP Query Routing Information Disclosure");
 
 script_set_attribute(attribute:"synopsis", value:
"The list of IP routes on the remote host can be obtained via SNMP." );
 script_set_attribute(attribute:"description", value:
"It is possible to obtain the routing information on the remote host
by sending SNMP requests with the OID 1.3.6.1.2.1.4.21

An attacker may use this information to gain more knowledge about the
network topology." );
 script_set_attribute(attribute:"solution", value:
"Disable the SNMP service on the remote host if you do not use it, or
filter incoming UDP packets going to this port." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/08/21");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_summary(english: "Enumerates routes via SNMP");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2008-2023 Tenable Network Security, Inc.");
 script_family(english: "SNMP");
 script_dependencies("snmp_settings.nasl", "find_service2.nasl");
 script_require_keys("SNMP/community");
 exit(0);
}

#

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

ipRouteInfo = make_list();
ri = 0;

# ipRouteInfo
roid = "1.3.6.1.2.1.4.21.1.1"; 
oid = roid;
while (1)
{
  v = snmp_request_next(socket: soc, community: community, oid: oid);
  if (isnull(v) || ! issameoid(origoid: roid, oid: v[0])) break;
  oid = v[0];
  ipRouteInfo[ri++] = v[1];
}

if (ri == 0 || ri == 1 && ipRouteInfo[0] == "0.0.0.0") exit(0);

ipRouteMask = make_list();
mi = 0;
# ipRouteMask
roid = "1.3.6.1.2.1.4.21.1.11";
oid = roid;
while (1)
{
  v = snmp_request_next(socket: soc, community: community, oid: oid);
  if (isnull(v) || ! issameoid(origoid: roid, oid: v[0])) break;
  oid = v[0];
  ipRouteMask[mi++] = v[1];
}

report = '\n';
for (i = 0; i < mi || i < ri; i ++)
  if (ipRouteInfo[i] != '0.0.0.0' || ipRouteMask[i] != '0.0.0.0')
    report = strcat(report, ipRouteInfo[i], '/', ipRouteMask[i], '\n');

security_note(port: port, proto: 'udp', extra: report);

