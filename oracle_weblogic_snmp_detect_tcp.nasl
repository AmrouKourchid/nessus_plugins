#TRUSTED 8a3c4d3c458a497c19b4be913380a5eb5a06d72c1317a934da9659ba4bbf694cb1a6c7b153736b85f12caed57355a50f33218f433dbb5699b7f6a7f3a4a521c3aac5ec91a7a8c45725f7bb33c1de36f59b5105aa0db2f5bbf0d87bf49035215f96da6a81224c5f68184eb7356fa98c68d5422045649aa37a4966b2a0fb7b5bdcf5a5ccccac89cc3ff89b78ba4f9c7643034eafb72a87205d148cbcedd1885b1c4f0def6148279a6878d9d6b536d09c885ffd920f854b931039996f7fb947e857a08cb0d6ebe01d38d822da6251add1f6a526038b83d511bc7cfbddbeab4e4703b044749faeb6b5d250ff69a898ca17cb05890a15489d8818e3b46ad6968cc981dffdd29c8ab17652575bbf316a4956c1197ce552c5258e3122b5d3d5a2ee953854ed083ecbb210b16b38199d7e0c4c0cc74bc7f8a31f690ac4d1485f7725a4d3ec4d09db00adba118ede54ef313a06a12d847040bf3135021adade677359a7fe2c54f8c20a1a3e6a8854619f36f2194b37525c95d64dd5c35c77cff54e561d7c1bb56c16c3e02226806b779c6dd4472f0747a23b7a83cca52f04a1af014f975504fbd5cf31baeb39d87207a03441d47a464eba6bed6317eb93e103eac20c25ddab5e9ad17a2fbc0145c7dc363fee9ff0ec621df2260ded934a7106218d82c970c789d08b80251321662bac7820aa39669258d97ba5947474d60a6a3d4dcb406d
#TRUST-RSA-SHA256 3c635401143c6beadd8b0fa1b4fd133cb71bcf98c5e42fcbb595b2d08522ab4d6bb1ab7278454a6428c92f4f997f6bfacff4d6ccb28ddad2d7777028a897cb4815f6cd85b995281c142896268f7b6a8dea648a6929faf1bd1647acfe994614c5e126cc28b5752caaf9f9834b9ccadbad3fa940ee9aedb377389dda0ffcb92949184fbc927f3f318a7f2692f3679eb2907dc8a1a23aba4863b1982abf370999879f2d8b9f248a8bb54831c3b5161337a886ee54899875c29f5f9038c94d0ff1217f4d6929587638332cdbb509df8139599de20cf2e157d7241ce0a24179e58815146a18a965e91f6dda3ba9d1b6fd5ff393aea8ff87c32c09449448d1cb81d052451b1dffe0a6d34b11340063ca4cca93ebdf8961b7c39bc4904bbaaf40c2d81bb179f9171e27e096724278aaa789613edbd3ff00e34dffe208c3e2e67447ac7cd79fa9b6c3f4cf8b1e40b60e8643613c1ab3970c987739097254e0f7d78b69e2989a601201c236dec7a9b97eb16f9c4c73802aed5226422c77473aabc1c39ff5e50e9e526f11813d94d89553c93c4ba9812e372b8a0a36e328246b62b12431fa9adebe7ec553a64632d536806983702fbf572a8a55316ec2ae404f0f3e1a15ae42c455f5411f9c27bffbbfd729c59536f098d7c5024f87f387b3d61ee8f6ba28a8c5f89ff2e8deccf1239c74e4aad20a85d910fc42ce859bfb6812994b7c6e4e
#
# (C) Tenable Network Security, Inc.
#

# snmpwalk -v2c -c public tcp:172.26.38.88:7001 .1.3.6.1.4.1.140.625.360.1.65
# snmpwalk -v2c -c public 172.26.24.85 .1.3.6.1.4.1.140.625.360.1.65 
# snmpwalk -v2c  -c public 172.26.38.11 .1.3.6.1.4.1.140.625.360.1.65

include("compat.inc");

if (description)
{
  script_id(109430);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/08");

  script_name(english:"Oracle WebLogic SNMP Detection (TCP)");
  script_summary(english:"Checks for Oracle WebLogic using SNMP (TCP)");

  script_set_attribute(attribute:"synopsis", value:
"An SNMP-based configuration utility was discovered on the remote
TCP port.");
  script_set_attribute(attribute:"description", value:
"Oracle WebLogic, a Java EE application server, was detected on the remote host.");
  script_set_attribute(attribute:"see_also", value:"https://docs.oracle.com/cd/E13222_01/wls/docs81/ConsoleHelp/snmp.html");  
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:bea:weblogic_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:weblogic_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2018-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_require_ports("SNMP/port", "www/possible_wls", 7001);
  script_dependencies("snmp_settings.nasl", "find_service2.nasl");
  exit(0);
}

include("snmp_func.inc");

# grab the user defined snmp
var snmp_ports = make_list(161, 7001);
if (!empty_or_null(get_kb_list("SNMP/port")))
{
  snmp_ports = make_list(snmp_ports, get_kb_list("SNMP/port"));
}

# grab the potential weblogic servers
var possible_wls_ports = get_kb_list('www/possible_wls');
if (!empty_or_null(possible_wls_ports))
{
  snmp_ports = make_list(snmp_ports, possible_wls_ports);
}

# remove dups and fork
snmp_ports = list_uniq(snmp_ports);
var port = branch(snmp_ports);

if (!get_tcp_port_state(port))
{
  audit(AUDIT_PORT_CLOSED, port, "TCP");
}

# Get the global community string for snmp
var community = get_kb_item("SNMP/community");
if (empty_or_null(community))
{
  community = "public";
}

var s = open_sock_tcp(port);
if (!s)
{ 
  audit(AUDIT_SOCK_FAIL, port, "TCP");
}

var oid = "1.3.6.1.4.1.140.625.360.1.65";
var snmp_resp = snmp_request_next(socket:s, community:community, oid:oid);
close(s);

if (empty_or_null(snmp_resp))
{
  audit(AUDIT_RESP_NOT, port, oid);
}

if ("WebLogic Server" >!< snmp_resp[1])
{
  audit(AUDIT_RESP_BAD, port, oid);
}

register_service(port:port, ipproto:"tcp", proto:"snmp");
set_kb_item(name:"snmp/weblogic/ports", value:port);
replace_kb_item(name:"snmp/weblogic/" + port +"/sysDesc", value:snmp_resp[1]);

var retlines = make_list();
var patches = "";
retlines = split(snmp_resp[1]);
var max = max_index( retlines );

var version = NULL;
for (var i = 0; i < max; i++)
{  
  if ("Patch" >!< retlines[i] && "patch" >!< retlines[i])
  {
    version = pregmatch(pattern:"WebLogic Server ([0-9\.]+) ", string:retlines[i]);
    if (!empty_or_null(version))
    {
      version = version[1];
      replace_kb_item(name:"snmp/weblogic/" + port + "/version", value:version);
    }
  }
  else
  {
    patches = patches + '   ' + retlines[i];
  }
}

var extra = 'The Oracle WebLogic Server has the following properties :' +
  '\n' +
  '\n Port                       : ' + port + '\n' +
  ' Protocol                   : TCP';

if (!empty_or_null(version))
{
  extra += '\n Version                    : ' + version;
}
extra += '\n';

if (patches != "")
{
  extra = extra + ' Patches                    :\n' + patches;
  set_kb_item(name:"snmp/weblogic/" + port + "/patches", value:patches);
}

security_report_v4(severity:SECURITY_NOTE, port:port, extra:extra);
