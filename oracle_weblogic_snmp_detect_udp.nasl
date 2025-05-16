#TRUSTED 5cd53069e5c71a68e068d61213b800a9f94bdacbd3fcaaaa3ddf4b2f30f2fbc643161c6a1325de38f30d138b81ad3f4f09a5e69a2b4ab8590be47583614784e9badbb87d7487f09504ab4765360bbe9c1f1cfe4daf1523da2a03d30ac2f12af79eef07c9c016369c769fce890dc78c58580335f3b404c6e1d062afaa987ec8c7c0f6ece6aecd3f04597fb56ba0ac37d7d3485bebdab5f5bb2ed1e93b9ccf3aa99e0745e028313ab682516e2024a8c29719587be1915a31c7398770e580335beb94fb8f4f5a4dbe3840db1bfcd27a882a37d3645f7fd25bf8d67ef3cbb61824c53e02ed55eb9a561f8994172ee07fe1eab6c164b5b101aa666c752c0ec64bee1a9ef5145f6c7bf68711884dff559244b4a2477e8bd743bdc650283eb9332847e96f2b462083552c71bc4c324451813e28c76eb55636f94bf019f98b10f834bae7e2a307da49461f1b1dea380c0286295f6fa9aa3e84cc592d8c39fe781be6f986fd77dc9ca2c47503d669a92291f40020498ea025b158155de11184f83e04220e6e8951bb970ce3bf45d9440535e946caba7ef99fc8b5afe60a1b73fb10bf5cb0ba5698764366510771469564b06a00d769794d3b398613aa4a48cce474f4d074805dfb9b1b67161d2118daf8caf6104a9a28cba804526be2d24d9fe224710b56de478969d3105b17c0b11060de021fbe95dd47e7e8f98ac9d0b9b68bd3ef3609
#TRUST-RSA-SHA256 0ae3cbf9d50c8606d69db4373c9e35a583bff5667a1c31410826e91db4ef1b8efd1244d3f9bd4fc93d5e4500400727de29b23361cf5f916a65e5cd487f6b4c49f15ca64549189523652d5aaadb429c9131637748affe6979dec2ed004fedead7e06fed159e2a6ccec6aad010db02fcc523fa90a699ab13a9413783614275976308db846af22f278607ae5a24fd0e347d984e3d71ea083843c50f2526041a689ace60c69710ec37d2ed5e240271d6baf6cb2f4dff69f5d241196157caa7ec99c095f5c2e10022b85b59382a4b244bfda2552467a275a0ed097a134bdda76a309311657ef82353672d06845567cba5c8b9c27c569bf549c4d26937e704db2ef96313ab90b37018f500e5d3bbc8b8e1374319a96bf64582f40229e6f3efcd3a92e9bac5bee74e105b281d914ef24e9466498b4ea8fd47179a5e53ae3e1b65d7dcb1861c4a6bf78b61255533cba3c8c5a5bc59121819f45fa4fff6b8af06c4f35ced9b6a008330db57fce867294ef5e433d3b63a076e195aa12dcd70941a0ac660f79dd39046a04d45891652028c19eb224a64915d875039c0a6714053185e8313fcfcfceddaa3cc3142220d52ecd39f87907d73989477edfd675446434832b3968f0aa1cf9bfc6a9209c6685ebd3bffdcd2a865d705d8f7fdefac91051a03a9ce6d1fc4c41a27b74225217b8555fd60b8791f27ded0af02991e969b7c282f8e9fd5
#
# (C) Tenable Network Security, Inc.
#

# snmpwalk -v2c -c public tcp:172.26.38.88:7001 .1.3.6.1.4.1.140.625.360.1.65
# snmpwalk -v2c -c public 172.26.24.85 .1.3.6.1.4.1.140.625.360.1.65 
# snmpwalk -v2c -c public 172.26.38.11 .1.3.6.1.4.1.140.625.360.1.65

include("compat.inc");

if (description)
{
  script_id(109431);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/08");

  script_name(english:"Oracle WebLogic SNMP Detection (UDP)");
  script_summary(english:"Checks for Oracle WebLogic using SNMP (UDP)");

  script_set_attribute(attribute:"synopsis", value:
"An SNMP-based configuration utility was discovered on the remote
UDP port.");
  script_set_attribute(attribute:"description", value:
"Oracle WebLogic, a Java EE application server, was detected on the remote host.");
  script_set_attribute(attribute:"see_also", value:"https://docs.oracle.com/cd/E13222_01/wls/docs81/ConsoleHelp/snmp.html");  
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:bea:weblogic_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:weblogic_server");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2018-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_require_udp_ports(161, "SNMP/port");
  script_dependencies("snmp_settings.nasl", "find_service2.nasl");
  exit(0);
}

include("snmp_func.inc");

var appname = "Oracle/WebLogic";

# grab the user defined snmp
var snmp_ports = make_list(161);
if (!empty_or_null(get_kb_list("SNMP/port")))
{
  snmp_ports = make_list(snmp_ports, get_kb_list("SNMP/port"));
}

# remove dups and fork
snmp_ports = list_uniq(snmp_ports);
var port = branch(snmp_ports);

if (!get_udp_port_state(port))
{
  audit(AUDIT_PORT_CLOSED, port, "UDP");
}

# Get the global community string for snmp
var community = get_kb_item("SNMP/community");
if (empty_or_null(community))
{
  community = "public";
}

var s = open_sock_udp(port);
if (!s)
{
  audit(AUDIT_SOCK_FAIL, port, "UDP");
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

register_service(port:port, ipproto:"udp", proto:"snmp");
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
