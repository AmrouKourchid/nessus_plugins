#TRUSTED a989052d3cc2eaefec5970135229d377ef9b89acfe7cc85eab9e4c39a10b976f3a5f558b9749d45dda0254cb092f9c539147c7c4a388c4b006e3121e63ec53fec1597574c357c884b34b373c92b6747ae7157ef8ca6f9825b33db67364cf1470a280bc3a342c953e9014dd8276f83731594372716b3ccfd256454244f725f690672ba3ce04ebf3456c0dd0d015143388844d560180b370105dfb52d6e4b5555bfa0ae30e0abd930b6fa28e57bbfd40ba07fd2c574e274d97a34a4b2954c31fe3d1522fde767354139ebf9e861cb9bc8a3c4b8e6fe5a6a243a261c06e065802627ef27d1c763dcdcf61f0e89dbb04c23e5998981ed768c394a570a5990894ecad6f6c60630bbd751ff6f4b03a6753cb860199b47d47a6fe39e9dd405cf9a3140b4bc56745f0c5a4d3d0289856f591475a386d6ee552f96b31563f57464160cd4ba633f2271d8a737f734007571f3d127db50f0abbc0f3af539166cd177b609a9a98c4e4a76003c2d2a95e7e9d152077bbb43248ce5e6a708e70c88eb1eaffcc98fa7c90c8994a10fa8d84a1b94008bbc2ff7aa10cbe29fce032ae454802c8612169a3b7ea5c4a70b06c5620f98fbec52f2937abf5b9e64263787c27e09ee5ffcebdc84b0750517bdfa507b875f5628eaf8ebf7673d057e8cb7748251ce34f7a7bebd50ccf5fd195f622faf83c3bc53d80808e7e82305905ba0a3f6e5d8e0b6f80
#TRUST-RSA-SHA256 06e44f9efb6370dd0bb59477e55f671b3e764c0f12abd64aef446130c1e9bcc49f4ef3b7546f8ea31e7bd8b0df291f021050bf64308943d1bd068abd4d1701642657d461f7a306a8252a72ec99a96d322860aa8fee26ee6d1e7ef1ca591bf033623b362e37056338821d2a55b71cf1d349fbe9d15c38c553ee507c5acd0ca363338dfdb4e30124b8eee7cda29b97380a9dc699e857e4706277d5f283c82a2ebedc3e9badbbe7f182742f1911de75d1c57bd6aed0abbeed05c846bf8784140a540a48e51a12f3de7243b64045eeb2cd8911d4e9beaddaa4b47a120c79ed90f9669c5eb37876b8be43bc0508b34ef7a3b911174752c5fd5c17a835aa9d0c2c1c248bca9e24c01d81b4df7de0b20381c5da1ac359f623c1cec1885f8416a8dc3afad52014d7583135eb0eec4435906ea647b71c1f5de3f3fdd88b016622383d2d8fe2abbcde85dad1418524bfd0ae175d4637be54998fd87ee4f9953b801515a3c6e0fb70f3a1b8b5faa7c49ff19f388dc814cceea231a05d426a6b309690bed2e9af9d010d54c17495605678f027504687918a81eed96fe294ed4eeac6c59c9930d70b3d9f6c53f45d676063a8fcd7d40e615de0836cededfaa4b1f7c31b42b361fccea5b4f0c034581bd0a5eca696c60ee584b734c99b0f39b9a265221b9d65ead8480cf0aa9c965237b021a00321c0b6136db3caddf0291911a0d4977a847d35
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72813);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/08");

  script_cve_id("CVE-2014-0329");
  script_bugtraq_id(65310);
  script_xref(name:"EDB-ID", value:"31527");

  script_name(english:"ZTE ZXV10 W300 Wireless Router Hard-coded Password");
  script_summary(english:"Tries to login using hard-coded credentials");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is using a known set of hard-coded credentials.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to login to the remote device using a known hard-coded
password (prepended with a portion of the device's MAC address obtained
from an SNMP request) for the admin account.  Attackers can exploit this
vulnerability to gain full control of the device.");
  # http://alguienenlafisi.blogspot.com/2014/02/hackeando-el-router-zte-zxv10-w300-v21.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?aad205ef");
  script_set_attribute(attribute:"see_also", value:"https://www.kb.cert.org/vuls/id/228886/");
  script_set_attribute(attribute:"solution", value:
"There is no known fix.  As a workaround, use firewall rules to block
SNMP and telnet access.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-0329");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:zte:zxv10_w300");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("snmp_settings.nasl", "find_service2.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");

  exit(0);
}

include("audit.inc");
include("default_account.inc");
include("global_settings.inc");
include("snmp_func.inc");

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

community = get_kb_item("SNMP/community");
if (!community) community = 'public';

port = get_kb_item("SNMP/port");
if (!port) port = 161;

if (!get_udp_port_state(port)) audit(AUDIT_PORT_CLOSED, "UDP", port);

soc = open_sock_udp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port, "UDP");

mac = NULL;

res = snmp_request (socket:soc, community:community, oid:"1.3.6.1.2.1.2.2.1.6.10000");

if (!isnull(res) && strlen(res) == 6)
  mac = hexstr(res);

if (isnull(mac) && islocalnet())
  mac = get_kb_item('ARP/mac_addr');

if (isnull(mac)) exit(0, 'Failed to determine the MAC address of the remote device.');

password = substr(toupper(str_replace(string:mac, find:':', replace:'')), 8, 11) + 'airocon';

affected = FALSE;
ssh_ports = get_service_port_list(svc: "ssh", default:22);
foreach port (ssh_ports)
{
  port = check_account(login:"admin",
                       password:password,
                       unix:FALSE,
                       cmd:"show status",
                       cmd_regex:"(System[^\$]*LAN Configuration[^\$]*WAN Configuration[^\$]*)\$",
                       out_regex_group: 1,
                       check_telnet: TRUE,
                       port:port,
                       svc:"ssh");
  if (port)
  {
    affected = TRUE;
    report = '\nNessus was able to login using the following credentials : \n' +
             '\n  Username : admin' +
             '\n  Password : ' + password + '\n' +
             default_account_report(cmd:"show status");
    security_report_v4(port:port, severity:SECURITY_HOLE, extra:report, proto:"udp");
  }
}
if(affected) exit(0);

# If no SSH ports were found to be vulnerable, try telnet.
telnet_ports = get_service_port_list(svc: "telnet", default:23);
foreach port (telnet_ports)
{
  port = check_account(login:"admin",
                       password:password,
                       unix:FALSE,
                       cmd:"show status",
                       cmd_regex:"(System[^\$]*LAN Configuration[^\$]*WAN Configuration[^\$]*)\$",
                       out_regex_group: 1,
                       check_telnet: TRUE,
                       port:port,
                       svc:"ssh");
  if (port)
  {
    affected = TRUE;
    report = '\nNessus was able to login using the following credentials : \n' +
             '\n  Username : admin' +
             '\n  Password : ' + password + '\n' +
             default_account_report(cmd:"show status");
    security_report_v4(port:port, severity:SECURITY_HOLE, extra:report, proto:"udp");
  }
}
if(!affected) audit(AUDIT_HOST_NOT, "affected");