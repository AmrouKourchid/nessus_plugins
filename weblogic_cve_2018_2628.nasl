#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(109429);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/16");

  script_cve_id("CVE-2018-2628");
  script_bugtraq_id(103776);
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/09/29");

  script_name(english:"Oracle WebLogic Server Deserialization RCE (CVE-2018-2628)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle WebLogic server is affected by a remote code
execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle WebLogic server is affected by a remote code
execution vulnerability in the Core Components subcomponent due to
unsafe deserialization of Java objects by the RMI registry. An
unauthenticated, remote attacker can exploit this, via a crafted Java
object, to execute arbitrary Java code in the context of the WebLogic
server.

Note that this plugin does not attempt to exploit this RCE directly
and instead checks for the presence of the patch Oracle supplied
in the April 2018 critical patch update (CPU).");
  # https://www.oracle.com/technetwork/security-advisory/cpuapr2018-3678067.html#AppendixFMW
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4e39ef65");
  script_set_attribute(attribute:"see_also", value:"https://github.com/brianwrf/CVE-2018-2628");
  script_set_attribute(attribute:"see_also", value:"https://github.com/shengqi158/CVE-2018-2628");
  # https://www.tenable.com/blog/critical-oracle-weblogic-server-flaw-still-not-patched
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9cf2dde7");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2018 Oracle
Critical Patch Update advisory.

Note that the patch for CVE-2018-2628 is reportedly incomplete.
Refer to Oracle for any additional patch instructions or
mitigation options.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-2628");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Oracle Weblogic Server Deserialization RCE');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:weblogic_server");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2018-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("weblogic_detect.nasl", "t3_detect.nasl");
  script_require_ports("Services/t3", 7001);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("t3.inc");


appname = "Oracle WebLogic Server";

port = get_service(svc:'t3', default:7001, exit_on_fail:TRUE);

# Try to talk T3 to the server
sock = open_sock_tcp(port);
if (!sock) audit(AUDIT_SOCK_FAIL, port);
version = t3_connect(sock:sock, port:port);

# Only 10.3.6.0, 12.1.3.0, 12.2.1.2 and 12.2.1.3 are affected
# i.e., 12.2.1.1 is not affected?
if (version !~ "^10\.3\.6\." &&
    version !~ "^12\.1\.3\." &&
    version !~ "^12\.2\.1\.2($|[^0-9])" &&
    version !~ "^12\.2\.1\.3($|[^0-9])")
{
  audit(AUDIT_INST_VER_NOT_VULN, appname, version);
}

# Send ident so we can move on to login
t3_send_ident_request(sock:sock, port:port);

# Send our "login request"
auth_request = '\x05\x65\x08\x00\x00\x00\x01\x00\x00\x00\x1b\x00\x00\x00\x5d\x01\x01\x00\x73\x72\x01\x78\x70\x73\x72\x02\x78\x70\x00\x00\x00\x00\x00\x00\x00\x00\x75\x72\x03\x78\x70\x00\x00\x00\x00\x78\x74\x00\x08\x77\x65\x62\x6c\x6f\x67\x69\x63\x75\x72\x04\x78\x70\x00\x00\x00\x0c\x9c\x97\x9a\x9a\x8c\x9a\x9b\xcf\xcf\x9b\x93\x9a\x74\x00\x08\x77\x65\x62\x6c\x6f\x67\x69\x63\x06\xfe\x01\x00\x00\xac\xed\x00\x05\x73\x72\x00\x1d\x77\x65\x62\x6c\x6f\x67\x69\x63\x2e\x72\x6a\x76\x6d\x2e\x43\x6c\x61\x73\x73\x54\x61\x62\x6c\x65\x45\x6e\x74\x72\x79\x2f\x52\x65\x81\x57\xf4\xf9\xed\x0c\x00\x00\x78\x70\x72\x00\x02\x5b\x42\xac\xf3\x17\xf8\x06\x08\x54\xe0\x02\x00\x00\x78\x70\x77\x02\x00\x00\x78\xfe\x01\x00\x00\xac\xed\x00\x05\x73\x72\x00\x1d\x77\x65\x62\x6c\x6f\x67\x69\x63\x2e\x72\x6a\x76\x6d\x2e\x43\x6c\x61\x73\x73\x54\x61\x62\x6c\x65\x45\x6e\x74\x72\x79\x2f\x52\x65\x81\x57\xf4\xf9\xed\x0c\x00\x00\x78\x70\x72\x00\x13\x5b\x4c\x6a\x61\x76\x61\x2e\x6c\x61\x6e\x67\x2e\x4f\x62\x6a\x65\x63\x74\x3b\x90\xce\x58\x9f\x10\x73\x29\x6c\x02\x00\x00\x78\x70\x77\x02\x00\x00\x78\xfe\x01\x00\x00\xac\xed\x00\x05\x73\x72\x00\x1d\x77\x65\x62\x6c\x6f\x67\x69\x63\x2e\x72\x6a\x76\x6d\x2e\x43\x6c\x61\x73\x73\x54\x61\x62\x6c\x65\x45\x6e\x74\x72\x79\x2f\x52\x65\x81\x57\xf4\xf9\xed\x0c\x00\x00\x78\x70\x72\x00\x10\x6a\x61\x76\x61\x2e\x75\x74\x69\x6c\x2e\x56\x65\x63\x74\x6f\x72\xd9\x97\x7d\x5b\x80\x3b\xaf\x01\x03\x00\x03\x49\x00\x11\x63\x61\x70\x61\x63\x69\x74\x79\x49\x6e\x63\x72\x65\x6d\x65\x6e\x74\x49\x00\x0c\x65\x6c\x65\x6d\x65\x6e\x74\x43\x6f\x75\x6e\x74\x5b\x00\x0b\x65\x6c\x65\x6d\x65\x6e\x74\x44\x61\x74\x61\x74\x00\x13\x5b\x4c\x6a\x61\x76\x61\x2f\x6c\x61\x6e\x67\x2f\x4f\x62\x6a\x65\x63\x74\x3b\x78\x70\x77\x02\x00\x00\x78\xfe\x01\x00\x00';


# Object to be de-serialized:
# sun.rmi.server.UnicastRef object with localhost:0 TCP endpoint
auth_request += 
'\xac\xed\x00\x05\x73\x72\x00\x19\x73\x75\x6e\x2e\x72\x6d\x69\x2e' +
'\x73\x65\x72\x76\x65\x72\x2e\x55\x6e\x69\x63\x61\x73\x74\x52\x65' +
'\x66\x72\x9b\xa1\xf1\x9d\x8f\x4e\x02\x0c\x00\x00\x78\x70\x77\x26' +
'\x00\x09\x6c\x6f\x63\x61\x6c\x68\x6f\x73\x74\x00\x00\x00\x00\x00' +
'\x00\x00\x00\x64\x86\x26\x2b\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
'\x00\x00\x00\x00\x00\x00\x78';

auth_request += '\xfe\x01\x00\x00\xac\xed\x00\x05\x73\x72\x00\x25\x77\x65\x62\x6c\x6f\x67\x69\x63\x2e\x72\x6a\x76\x6d\x2e\x49\x6d\x6d\x75\x74\x61\x62\x6c\x65\x53\x65\x72\x76\x69\x63\x65\x43\x6f\x6e\x74\x65\x78\x74\xdd\xcb\xa8\x70\x63\x86\xf0\xba\x0c\x00\x00\x78\x72\x00\x29\x77\x65\x62\x6c\x6f\x67\x69\x63\x2e\x72\x6d\x69\x2e\x70\x72\x6f\x76\x69\x64\x65\x72\x2e\x42\x61\x73\x69\x63\x53\x65\x72\x76\x69\x63\x65\x43\x6f\x6e\x74\x65\x78\x74\xe4\x63\x22\x36\xc5\xd4\xa7\x1e\x0c\x00\x00\x78\x70\x77\x02\x06\x00\x73\x72\x00\x26\x77\x65\x62\x6c\x6f\x67\x69\x63\x2e\x72\x6d\x69\x2e\x69\x6e\x74\x65\x72\x6e\x61\x6c\x2e\x4d\x65\x74\x68\x6f\x64\x44\x65\x73\x63\x72\x69\x70\x74\x6f\x72\x12\x48\x5a\x82\x8a\xf7\xf6\x7b\x0c\x00\x00\x78\x70\x77\x34\x00\x2e\x61\x75\x74\x68\x65\x6e\x74\x69\x63\x61\x74\x65\x28\x4c\x77\x65\x62\x6c\x6f\x67\x69\x63\x2e\x73\x65\x63\x75\x72\x69\x74\x79\x2e\x61\x63\x6c\x2e\x55\x73\x65\x72\x49\x6e\x66\x6f\x3b\x29\x00\x00\x00\x1b\x78\x78\xfe\x00\xff';
send_t3(sock:sock, data:auth_request);
ret = recv_t3(sock:sock);
close(sock);

if (isnull(ret) || 'sun.rmi.server.UnicastRef cannot be cast to weblogic' >!< ret)
{
  audit(AUDIT_INST_VER_NOT_VULN, appname, version);
}

report =
  '\nNessus was able to exploit a Java deserialization vulnerability by' +
  '\nsending a crafted Java object.' +
  '\n';
security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
