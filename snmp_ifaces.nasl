#TRUSTED 6b714edcf18cb14ba26e410b222849d92be18675478a836b1c8ebf33d4ff33287b872436c8f0045e05a5b15072d4c2fb80d7770380c2c4ac9611b82f70cc74b171b02dbf49e1518d8db38cf2ac56312e69f5dcbcedc149aceebd56836abce3bf1b14d41064d565989385edc15581a0b7e8fc77434b95d7724ac7829a4ea39cc69e7a3f2b02fb694c8eb34dc7e84412b205b00ca9cf820e31ea0cefc71f0a1357cbe85bc45774e978d6a1b4a7c0bbe9d97a721741a99ed3f4b3127fdcc6c403686744a63f7ffaacdfd04297d30ddec144daab8f0c571b18b1715084ed363fbda607851b0674e12f133fb397808d4ee228079d7a55cd4b122baafdb0a11edd6847290212bf4976123ce214efe489048d6bdfc331b21e0cb4ac59308ab78e38a28b4257599aec8ad5f59e0956517947cbc4f25a2cbf915d6da3ceb28a7e509160850652e2615f2546b356a303ea8e13c21aa0f8e019ca8c3bf9b5a5961c5658fc27ec59b0496c762ecc770cfd45f2e3c65c4e472079493c417c6aed19190e4c6fd03bbdfc7c6dfdd75fa09eec4d2882ce6f814b670d472d0dc07109828829d931acd92b00ecb6ae9f4792f3cd928445e481034d173eed90be1e8902923fdbe4925728d0482e47bc02f54d0eeff81668bf7c5f92caecc860f5ec0c003a96ec7d337628e627a879b1e87407e71b25ba64d38da3f8d387490622ab005709937d7b040b
#TRUST-RSA-SHA256 5c22a529509fe2ef95bf2aef38450baf561d09f29c22e78dd76a915d9660e8c12f1baa7a8ec3d55939843e294bd1434fb6f5e3e6bf1369b39f533f67e33631fe279dd9b62c4fd8116c57bbeff610494a96c0274ff5b975cdabb0528f0bd74caf2253c356ca46cc4feb871298ed14c4baebf78bf125e48d3b6f6d487869edad51a0d5d15298d8980a21e912e3e971a77e36b327f70f2d4cecbe41b2a5097c89cda3c402295f68e962efce8773d82eaf4f277040ee880982fe0cbd3eb01a91e50e77cb246b8fbe191503f9d4c56ddb4f9f365541db6c547e97f1d61e12edf9d0be7f3f36fd503aab5709de912a273d1b80c06943f294a3d4876a2a85bdca798787875e61cd3a584c2fa8f20dc377eeee9edfb248298b66d6f9f41a5b5d12dbcc20db3d6778f1e72102d8733fe8c608c6bcdcd8c192c233f7d88103da4bb32528414ef6502d846debb924d2f2e449b85d0252ee1766d2294c2b0ffc74db3e9a702becdecd16bee04f9e9b9a42dc30742cf102522d3f664ae902a21870a40e58497655c179d9f7fdbd90ce63bf2b8c222cbe1b79b8fe4656506133648c8d007061e3f074a271747f7778213b4a36d0dd3af1bf6450ec5c3da738bdc3a36940ed84a6757169fe59e39b3ba32a1719e6794956ab27d1239b378406b337e72f3f306b4a5f2a66ddbc270027868285e51205e70627687f4193e80800e43399479fd302ac
#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10551);
 script_version("1.32");
 script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/08");
 
 script_name(english:"SNMP Request Network Interfaces Enumeration");
 
 script_set_attribute(attribute:"synopsis", value:
"The list of network interfaces cards of the remote host can be obtained via
SNMP." );
 script_set_attribute(attribute:"description", value:
"It is possible to obtain the list of the network interfaces installed
on the remote host by sending SNMP requests with the OID 1.3.6.1.2.1.2.1.0

An attacker may use this information to gain more knowledge about
the target host." );
 script_set_attribute(attribute:"solution", value:
"Disable the SNMP service on the remote host if you do not use it,
or filter incoming UDP packets going to this port." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2000/11/13");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"Enumerates processes via SNMP");
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
if(!community) exit(0);

port = get_kb_item("SNMP/port");
if(!port)port = 161;
if (! get_udp_port_state(port)) exit(0, "UDP port "+port+" is not open.");

soc = open_sock_udp(port);
if (!soc)
  exit (0);


number = snmp_request (socket:soc, community:community, oid:"1.3.6.1.2.1.2.1.0");
oid = "1.3.6.1.2.1.2.1.0";

network = NULL;

cnt = 0;

for (i=1; i<=number; i++)
{
 index = snmp_request_next (socket:soc, community:community, oid:oid);
 if ( index == NULL ) break;
 descr = snmp_request (socket:soc, community:community, oid:'1.3.6.1.2.1.2.2.1.2.'+index[1]);
 phys = snmp_request (socket:soc, community:community, oid:'1.3.6.1.2.1.2.2.1.6.'+index[1]);

 oid = index[0];

 network += strcat(
 '\n Interface ', i, ' information :\n',
 ' ifIndex       : ', index[1], '\n',
 ' ifDescr       : ', descr, '\n',
 ' ifPhysAddress : ', hexstr(phys), '\n',
 '\n'
 );

 if (strlen(phys) == 6 )
 {
   str = hexstr(phys[0]) + ':' + hexstr(phys[1]) + ':' + hexstr(phys[2]) + ':' + hexstr(phys[3]) + ':' + hexstr(phys[4]) + ':' + hexstr(phys[5]); 
  set_kb_item(name:"SNMP/ifPhysAddress/" + cnt, value:str);
  cnt++;
 }
}


if(strlen(network))
{
 security_note(port:port, extra:network, protocol:"udp");
}
