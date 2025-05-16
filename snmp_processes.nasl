#TRUSTED 65093dd2fe020062d5d0fd2942ffa13790fc4a74a2186a8f62b7bb46c6e57516717dfaf02c30b2c31c77dfe0ef9a0e55d7333d70d6e68bdb174029a5273e39e91becf1c55244ba06f3313b91c409d6459e5d3915737c3d96a6be7e937c593e161dcfbd9f369f050cddcefa35eeef56a560ab1ca9d55b3136d347a71325eaa54e6e107024a4dfbb29d94c85d21a031339f6ebfbea80b883821676a9ca423cd4a219659ce793abd1c615d738c5ee5cd812035cc392bba23aafcf9c35cdd866ad05bf61901f9fae76c05de767d82ff3625500e1400649630b791ca81b27aa1e5be4fd55ae7dce7cb3598a08b7008fbc2869e91da2e2f618ca50fd5792f70191ab7f7a79b5368474b2940865172caffd37727805e52157607950292f40fa90fd5ee69ae9f77bd29f10612e4a4753de98ad230cdd204bb544f7f546c3bea649db95a10d3c1c7bcdf9f4c09825dfc39d7299978a4de78bf5ded3986ec40459b8d01927de98d41c0e1c815022655e55e4d059513679f7395a53c8f466f02347167cc984cb8aa20e307dc8ed54cd327905bf4f7b2f8c9223ec24ef9ebe0d860f39f48c1f338a748deec3c8fe296317822b7e4f2956cad5540df04053aeec14882e7e7c8d68090efcc559d91df1a7832b28e94002aaaae891c60cc703dc4501f8af1518037fbd050ee219d0bb011eec1b6799ad2a5e4a4e49617a3743afeb446e3a5e0027
#TRUST-RSA-SHA256 9f57e30af94be9d8b11d8b7efa51437b80b03c322059bc8cb763e59781b6ed3b29789e91879b6399b0ea77cde4de33a079ae712b0a3461b6d6f52173c7dbe19ec7f4b07e805f2056bb2f93bb8c178ed9136387ce8c810ef96f789bd5daac768159c0964130188d7a9ac8f83121ff35151c90fcc2bfb6b262e0e7fe6c6525c2278156af06f61e2af993bf6bedd5d81a25a6a318c2885b50e8ddc70344fd3e28728e3b5e09de7403fc68dde6526e2d7c897199b8665086bed94b391fa708908cc73684e7e0aaaca99cf63594408aa7cc858379ef4145eee5185921a7d001c58dcf10123aa6229e539e58b994ee9325c22e29a0e08b20b389ff22f411ebf2a24613389fb35aa0707271f29006602dd8243697771c64de89a86b3eed831fe4270e4b773502c8f77fa9ded5fe9cf3649bfa06ef4c5c03668bfc53fbee2f33bc03d0bd371ee6bfdc1764da6d95c13f9d169d90a2d0caab874fb66fc1ddedfceeab8a0622a800a6e325d30adf9047eed6802326ca307a91221f988fc0a6b87eec3826dbdf3a1345187bfdf6e106ae35efb0d9d8aa2a76786ce4c6818972bcfcd67b94e32dab89902560f97310b9d2addd3eb5d0a4da7639f0ca7ffc3b73b26ea004eb23a5bd240460b3c41354b788f39d1e4733d641d82a46171300237e60dfa0a815425460d8230b34f4610e4cb751982ad74e4f6aa2c64fc4916a1f9fd6e913e219d8
#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10550);
 script_version("1.27");
 script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/08");
 
 script_name(english:"SNMP Query Running Process List Disclosure");
 
 script_set_attribute(attribute:"synopsis", value:
"The list of processes running on the remote host can be obtained via SNMP." );
 script_set_attribute(attribute:"description", value:
"It is possible to obtain the list of running processes on the remote
host by sending SNMP requests with the OID 1.3.6.1.2.1.25.4.2.1.2

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

community = get_kb_item_or_exit("SNMP/community");

port = get_kb_item("SNMP/port");
if (!port) port = 161;
if (! get_udp_port_state(port)) exit(0, "UDP port "+port+" is not open.");

soc = open_sock_udp(port);
if (! soc) exit (1, "Could not open socket to UDP port "+port+".");

oid = "1.3.6.1.2.1.25.4.2.1.2";

soid = oid;
re =  strcat("^",str_replace(string:oid, find:".", replace:'\\.'), '\\.');

report = '';
while(1)
{
  z = snmp_request_next (socket:soc, community:community, oid:soid);
  if (!isnull(z) && egrep (pattern:re,string:z[0]))
  {
   name = z[1];
   soid = z[0];
   p = z[0] - (oid+'.');
   cmdline = snmp_request(socket: soc, community:community, 
   	  oid:  '1.3.6.1.2.1.25.4.2.1.5.'+p);
   cpu = snmp_request(socket: soc, community:community, 
       oid: '1.3.6.1.2.1.25.5.1.1.1.'+p);
   cpu = int(cpu) / 100; cpu = strcat(cpu);
   mem = snmp_request(socket: soc, community:community, 
       oid: '1.3.6.1.2.1.25.5.1.1.2.'+p);
   mem = strcat(mem);
   t1 = 5 - strlen(p); if (t1 < 0) t1 = 0;
   t2 = 6 - strlen(cpu); if (t2 < 1) t2 = 1;
   t3 = 6 - strlen(mem); if (t3 < 1) t3 = 1;
   t4 = 16 - strlen(name); if (t4 < 1) t4 = 1;
   report = strcat(report,
   	  crap(data:' ', length: t1), p, 
   	  crap(data:' ', length: t2), cpu, 
	  crap(data:' ', length: t3), mem,
	  ' ', name, crap(data:' ', length: t4),
	  cmdline, '\n');
  }
  else
    break;
 }

if (strlen(report) > 0)
{
  report = strcat('\n  PID   CPU   MEM COMMAND           ARGS\n', report);
  security_note(port:port, extra:report, protocol:"udp");
}
