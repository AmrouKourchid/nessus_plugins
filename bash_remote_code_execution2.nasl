#TRUSTED 6118bd0ae85d5ceaef3f7c1c2abc5a432341aec62c85a6412cdf2145f49767ec473ff13b82240148810ac3139a0692d64c0dbacbe0ec5c8abb48b134811b590803439d181e5f8329aef3b01d7156850093460927ebd4c079c34fd034a04d71e39138fd9445445d7e1ae95419c299f9e39b439e5ede40c2134882912e1ade2dba054cfed66065e6c7d8c017e695db2d99a6510a7ee1131834eb4bcf807640f208e2a056d1c99a2e2be29c3077312530d274bd9432af33888b2b55d0d52ac69d35c4f81a3bb50599e010cc7ba8c1d8ff7f3c352545113b7143d699816ec877c32fc23ed5c1b16e26ecd1065ccb2a3105d67b94a9c1c833ef91e4eacd8755eb55ef1cecbcb23e0a1ce75b5933f9561662d7d422a4cc54c8d408027fd0c1a8a12d4d9b4b359cf0cabdcc33518ef057d999762cd0334a90d96df0dc0792cbe30c2467c7fd88f389ea99104e3726b65fe537ffc7686ff6db0cd847fc2cac827b41cf01ee3478e2e4d93d3b1961ff650a67c7bc50dc66d6ce6dec70c27efe3500aadb368b9ea916d59806f82e8815a35f4bbd7d1162de53a137b89e9e0a58430ca3fdf733be30624183ab6da627668d9b528d3dca608ded8ca1024654d26d2191c40a1eb7786e807f48b05c1142a237b76a82b91463f42850b6c932f6e7c6a881ed7cab9bc302289df1cc5c7f436e75ebd74029e3fc280e11ec89576b28d2fe4ae9c850
#TRUST-RSA-SHA256 6c0232dcd8e21d8abf573871b791519052802c4f6fe4d9a5e24a92f14e6b254474def125c8e54c9ffcf7e883196d0b66a2e2e7c21e422ce3783306f07c3c3dbb9cc9341a12e00ca3e476079f2c76c4f88e57b29195db5983ae7b51e7f05f98f7162f4726d570cad7af9656adf1c9b594c807ad2292193ccf58f2e28022ae2cde1e626e8e9346cebfe4a3f8ae1b05fcec72d3b448ffe606a00c9546097fedbc0bfb683eeb388bb0b38a2ce3a09248cb67e08fb4a40685ee67ad61a970b7fcb2217d37a49b94d07aa9c967e7e4507e5a8c97df11dc4c98c0d68b6076de7eb8619f8383af8bb4acce9e14a16bad83b62c82b1afbdd2c72d72f97da1101071cf19a068a68d919946952136163a417d9bbe8f479199f95183f05db5a8fe18c8126204b8fb912dade2eb28fb894b338e4cfd8bf3d0998d1e3cd4185a7cda846b1c69b3fd4aba6b65778774ee5de088d04da2ade34ac572f0e0809e22bf66ed52529adf4e9cb08b3e61244b4e8bc0d2ce2aeaebb53113e1c570b7e55fb31cffe26d8a194b7145b18ee8dc9d12861753d8ba1cf524e243c67ad7dd6cd67f98e93d348a82552d2df67733939c91c79cffc86060c8ae568159217f5693814752cf9f6c79ec2779bb2eaa5381764a9092b878eb9bb7e9e0ff596a5355a82daf0ac35e0dd6ea89b03e9b1ccff70f20346af339f903180ab5748707e6ae9a57a00036fa380756
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78067);
  script_version("1.36");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_cve_id("CVE-2014-6277", "CVE-2014-6278");
  script_bugtraq_id(70165, 70166);
  script_xref(name:"CERT", value:"252743");
  script_xref(name:"IAVA", value:"2014-A-0142");
  script_xref(name:"EDB-ID", value:"34860");

  script_name(english:"Bash Remote Code Execution (CVE-2014-6277 / CVE-2014-6278) (Shellshock)");
  script_summary(english:"Logs in with SSH.");

  script_set_attribute(attribute:"synopsis", value:
"A system shell on the remote host is vulnerable to command injection.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Bash that is vulnerable to
command injection via environment variable manipulation. Depending on
the configuration of the system, an attacker could remotely execute
arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/fulldisclosure/2014/Oct/9");
  # http://lcamtuf.blogspot.com/2014/10/bash-bug-how-we-finally-cracked.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e40f2f5a");
  script_set_attribute(attribute:"solution", value:
"Update Bash.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-6277");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'CUPS Filter Bash Environment Variable Code Injection (Shellshock)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:gnu:bash");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"Gain a shell remotely");

  script_copyright(english:"This script is Copyright (C) 2014-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("ssh_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");
include("misc_func.inc");


enable_ssh_wrappers();

function report_and_exit(port, command, output, patch_check)
{
  local_var hdr, report;

  report = NULL;
  if (report_verbosity > 0)
  {
    hdr =
    '\n' + 'Nessus was able to login via SSH and run the following command :' +
    '\n' +
    '\n' + command;

    report =
      hdr  +
      '\n' +
      '\n' + 'and read the output :' +
      '\n' +
      '\n' + output +
      '\n';

    if(patch_check)
    {
      report +=
        'This indicates that the patch for CVE-2014-6277 and ' +
        '\n' + 'CVE-2014-6278 is not installed.';
    }

  }
  security_hole(port:port, extra:report);
  exit(0);
}


if ( islocalhost() )
{
 info_t = INFO_LOCAL;
}
else
{
 ret = ssh_open_connection();
 if ( !ret ) audit(AUDIT_FN_FAIL, 'ssh_open_connection');
 info_t = INFO_SSH;
 if(info_t == INFO_SSH) ssh_close_connection();
}

port = get_service(svc:"ssh", default:22, exit_on_fail:TRUE);
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

ret = ssh_open_connection();
if ( !ret ) audit(AUDIT_FN_FAIL, 'ssh_open_connection');

# Check CVE-2014-6277
#
# - We check CVE-2014-6277 first because this CVE covers some older
#   bash versions while CVE-2014-6278 doesn't, according to
#   http://lcamtuf.blogspot.com/2014/10/bash-bug-how-we-finally-cracked.html.
#
# - The CVE-2014-6277 PoC produces a segfault.

command = 'E="() { x() { _; }; x() { _; } <<A; }"' + ' bash -c E';
output = ssh_cmd(cmd:command, noexec:TRUE);

if( "egmentation fault" >< output
 || "egmentation Fault" >< output) # Solaris
{
  if(info_t == INFO_SSH) ssh_close_connection();
  report_and_exit(port:port, command: command, output: output);
}

# Problem reported on AIX 6.1 TL 8 SP 1 with bash 4.3.7 (redmine 10989)
# Disable CVE-2014-6278 check for now

# CVE-2014-6277 detection fails, try to detect CVE-2014-6278,
# This CVE appears to work against bash 4.2 and 4.3.,
# but not against 4.1 or below.
#
#test_command = "echo Plugin output: $((1+1))";
#command = "E='() { _; } >_[$($())] { " + test_command + "; }' bash -c E";
#output = ssh_cmd(cmd:command);

#if ("Plugin output: 2" >< output) vuln_6278 = TRUE;

# ok we detected CVE-2014-6278, send another command
# hoping to get a more convincing output
#if(vuln_6278)
#{
#  test_command = "/usr/bin/id";
#  command2 = "E='() { _; } >_[$($())] { " + test_command + "; }' bash -c E";
#  output2 = ssh_cmd(cmd:command2);
#  if (output2 =~ "uid=[0-9]+.*gid=[0-9]+.*")
#  {
#    command = command2;
#    output  = output2;
#  }
#  report_and_exit(port:port, command:command, output:output);
#}

# If we still cannot detect CVE-2014-6277 or CVE-2014-6278,
# we try to determine if the patch for these CVEs has been applied.
command = "E='() { echo not patched; }' bash -c E";
output = ssh_cmd(cmd:command);
if(info_t == INFO_SSH) ssh_close_connection();

# Patch not installed
# Ignore cases where the host returns an "unknown command" error and returns the entire command
if (("not patched" >< output) && ("echo not patched" >!< output))
  report_and_exit(port:port, command:command, output:output, patch_check:TRUE);
# Patch installed
else audit(AUDIT_HOST_NOT, "affected.");


