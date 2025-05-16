#TRUSTED 3bb668e9a648d8c805279cdbf0b14d8ab0559665ca6aa0f05db5738b44622b76a5b2cb1c4d5ca53e95e94293358e848bea67dca663a29787730a562c16bdf4b148e6404c730652ef1e4091f6ba292c9e3a1ad832e709c64f7dbd05bb5b33cf4776199e4ffac347e35cbeac59e4eb6591ed7b542e0ff7fd2da9b0baaf8ee8c0cbc47635cb7e271a0b6afc641c2f083837dcec533f978984e97f94fe238df3eeb250b23506480f519f23d6b7fb7aa2358945640882bec5388c1197da01f2413c44a00533a5cc195b1d03dca701db74425913ff1e536be53ab85732b9507761b0d63179f62e21b6f950930d241422a2c419239c07cf61311674cef62d03ecac1935978bd681b43e82640901e852160b016274d3148c460964aa00c57ada143ccbaefd84045797ac9e637f5ff24a3a1858cbc5afc1eee7a134df5e3bfa289b421bbfd9ce671022687e557e86b7ba1634ae47c2eaa0a40eda5034969a0bed531a1f531cd16093e425e27f7bcfdc95f16bdf108c0a7806089384de5538a79f51b175cf7ec8238bf00ec5127137b52e6d825081a7ba5a045c018d5e4afc9442cebb73399f43b3fcd911deb951998a25987b59aa673da9234e141b9306e0444b4fe0b70d9575cc5452abe6c49f4f9805785854fd515c2a3c2c60543c24dcb8d3c3dcd7fa5f0536765ef080de3930df1e118b6d21d0bad69de7eb0b565a01e76c3f573787
#TRUST-RSA-SHA256 615e557bbbbb874492df3458a9a26d98769a593c67a795f04349be258f7f9d7fad7b83b4631b2ddc71b3a6e649336d75338961b2bec765fefc318f2d90a080f21cf4a22439d0afd4aea4a326ae758271993d323403dd60ce59fabcb2f4d6d0aae9ab1012fd8dce5e7d98a25031520ce3f06a39c158d642e701f509ae1857b589313415b278e9fa5bcd8a1eace1a9e61ffa7adabd3a3e988bf87dfd949cafcf5e3d906a301474ba7f1a91c133a8c61aac67be32beff46e1b4267dbece4897d2cefbec331462b3319a924854787c25e1428045f1b49311dd73802ac2129062e77b0f6201cdccb639fae1e34d04aa3aa8cd31550ae681141f7833f8244533a9addc803b18d462ea20e6ad5f503b287ff37de9b3a94ca60c3837b0c5a7edcf845b04fb36b0d41e4463f422f2935ee59b4b9b862ea3a42da8b90ffbd7d21d773494a595d06d388202545fd44a55ab58d51a2d96cfe2a488b019824b95229c118f86759aa77fbcf8f36a6243566ea7e7a04e8d2ad4a3d42324e17b5b51f048e9c1a8aa2aefccefc722dca9bac7fed9d6bfd46d5f49327f5bef32b9c06e44d9317d456781013943c8bfb884ac81a36b5e2334bd25a70d932b881065cb632f409bc2637509a6f2b0b8d80d25fc6d2bd9b7d24312a5aa649bb0287d3eae3cc36c8a5f4e71988f8e730db1a4a3a8f02f94f31f6f29ec7ea5a99f2bb0c0e059f1899a484967
#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(45022);
 script_version("1.5");
 script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/08");
 
 script_name(english:"SNMP Query Airport Version");
 
 script_set_attribute(attribute:"synopsis", value:
"The version of the remote Airport device can be obtained via SNMP." );
 script_set_attribute(attribute:"description", value:
"It is possible to obtain the version and model type of the remote
Airport device by sending SNMP requests to the remote host. 

An attacker may use this information to gain more knowledge about the
target network." );
 script_set_attribute(attribute:"solution", value:
"Disable the SNMP service on the remote host if you do not use it, or
filter incoming UDP packets going to this port." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/03/10" );
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"asset_inventory", value:"True");
 script_end_attributes();

 script_summary(english:"Enumerates system info via SNMP");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2010-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if(!port) port = 161;
if (!get_udp_port_state(port)) exit(1, "UDP port "+port+" is not open.");

soc = open_sock_udp(port);
if (!soc)
  exit(1, "Failed to open a socket on UDP port "+port+"."); 


model = snmp_request (socket:soc, community:community, oid:"1.3.6.1.4.1.63.501.3.1.1.0");
if ( isnull(model) ) exit(0, "Not an Airport Device.");
firmware = snmp_request (socket:soc, community:community, oid:"1.3.6.1.4.1.63.501.3.1.5.0");
 
report = "";
if ( model && firmware )
{
 set_kb_item(name:"Host/Airport/Firmware", value:firmware);
 report += 'Device name : '  + model + '\n';
 report += 'Firmware version : ' + firmware + '\n';
 is_dhcp = snmp_request (socket:soc, community:community, oid:"1.3.6.1.4.1.63.501.3.3.1.0");
 if ( is_dhcp == 0 ) report += 'DHCP Server : NO\n';
 else {
  report += 'DHCP Server : YES\n';
  oid = soid = "1.3.6.1.4.1.63.501.3.3.2.1.2";
  seen = make_array();
  num = 0;
  while ( TRUE )
  {
   num ++;
   if ( num > 50 ) break;
   v = snmp_request_next(socket:soc, community:community, oid:soid);
   if ( isnull(v) ) break;
   if ( !issameoid(origoid:oid, oid:v[0]) ) break;
   if ( !isnull(seen[v[1]]) ) break;
   toid = str_replace(string:v[0], find:"1.3.6.1.4.1.63.501.3.3.2.1.2", replace:"1.3.6.1.4.1.63.501.3.3.2.1.1");
   mac = snmp_request(socket:soc, community:community, oid:toid);
   seen[v[1]] = mac;
   soid = v[0];
  }

  if ( max_index(keys(seen)) > 0 )
  {
  report += 'List of IP addresses handed out by the DHCP server :\n';
  foreach item ( sort(keys(seen)) )
   report += 'IP address : ' + item + ', MAC address : ' + seen[item] + '\n';
  }
 }
 security_note(port:port, extra:report, proto:"udp");
}

