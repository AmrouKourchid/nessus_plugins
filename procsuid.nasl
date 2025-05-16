#TRUSTED 8c64fad29b7b90d14b6c0108ccd51e40e8de233d6ad8c44a774feddb0bc741c80d80e87d24d077deaeffc6138f4a72c0064f42dd01070d068bf0faa05c1351a536ae70f8fb3b7e1e065c5c6a9185cc1a63678624df0b0c3f9549b8e4330404922b1b4b9355380881e808da0ce9317189ea0f180137bf97fded6e86f2d880625566cb22dff3e91a249ce82dfdf8a257dbf1becc8ba97e4778bf488a7d251b238ae9217d9f40e8d7bc1ffc87b6c0e525ec2cc10e9444e9bd436cc9968c81f1138516692679efee2d02f8d6995e57ab106df711a3203100b89cc3ec170899f85d250efb9be3eca2eefa2657b1fcf956167aa9a08de860f044d8394e2b59f030505f2f8cfc8b0ac4174c40e4fc2abc0121ddc2a70bd4797bc93a189a17810e2d94b8b18d551f0fe23b5988b4bf4f51e4edbd72158746a8927238fe75d43c62abe136aa023472334a970f04d5fccd6006de92ffaa70eb5e3933ef77a23260da64f73daf7cdd72ccba0fcabcb5478b67107e1b2c614cd79915f7ddbe7f6cc3e57d739f0145c8d2c5fa9cecb22999e444170f2a2c4274c3027808af4268a1f00ee71040f7ca0ab1ecbbc23d072602cb56b4168be49d28615db2027cd115e9ee4a75e070be3c3b69bf3996f978cdfd34538da3d8e22dd6a18c05e11c4f00202617d3588e809542cd5057ffeeb122b8ead394eaf7a30b0920131ce4bc2da9c6d7676a46aa
#TRUST-RSA-SHA256 a47c1910ee7dc29d801a7b7b961cfe417e1fa2f2cda2375e3fe839f59b3173ff99e1a0321d5ebf5cfbeb3b9e1d269e8ce4b6e1a4e1ce4e74dcb786e1ca292915a1597ee7b94a23b348df542cf6e8b6641b8435dd50dc41215da7cef00d8ab28b4947a918ef2d8aa5779876d50b7099c931d1a392509c0c222fe721ad0454a2104455afa5a8c0f5e69997295d22b68d9860fde3354b57d490087a8b482cfb28c36bbb455eaa21bb16f51ed897482afb55cad3415fcdb5305402f1192e4aa4d24c931858c1200512a7be7cae730ccc11f07cae66dd9ddfe47eb6c47f32b1081c4dabe41ca4b369af898a9806d60a7051c7572a9eafced3defc8f473b1fd3e102eb7ad87fa76dd446e4fd3136d11b9032d75ebe936e97c5ecb65069b1bdd8959e31ef4ee65d768aa3e221c7902510e52b64291a54e4b83390930d115c0319b32afa94075eebde23bb02834c7e6f18a6a0f241910d7150983b828bc38248f296de3dd30d6562c3de08a76bde5ef3113ddca4f82517d0745a03d9e58bf390d396ddc7859c0da97898a8dcba74e39e39544237a56e1480aa2e8552312e6221497d0705e365db205eb386c8388cd9e55070fdfaa92a5a3be6d76337e2de660f3c2515193d8e4206a910f4ca0146c59316353d3964eaa49292280972d2dca0d684edfbe7955e0000a3f88cd4314a5564a5913c127186cc346f5ee4f6f06066b216897323
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100571);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/24");

  script_name(english:"suidperl Privilege Escalation (PROCSUID)");
  script_summary(english:"Checks for an installation of suidperl.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The suidperl application is installed on the remote host. It is,
therefore, affected by a privilege escalation vulnerability that
allows a local attacker to gain root privileges.

PROCSUID is one of multiple Equation Group vulnerabilities and
exploits disclosed on 2017/04/08 by a group known as the Shadow
Brokers.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/x0rz/EQGRP");
  script_set_attribute(attribute:"solution", value:
"Remove the affected software.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Manual analysis of the vulnerability");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/01");

  script_set_attribute(attribute:"agent", value:"unix");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:perl:suid");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017-2024 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('ssh_func.inc');
include('ssh_globals.inc');

enable_ssh_wrappers();

vuln = 0;

  distros = make_list(
    "Host/AIX/lslpp",
    "Host/AmazonLinux/rpm-list",
    "Host/CentOS/rpm-list",
    "Host/Debian/dpkg-l",
    "Host/FreeBSD/pkg_info",
    "Host/Gentoo/qpkg-list",
    "Host/HP-UX/swlist",
    "Host/MacOSX/packages",
    "Host/Mandrake/rpm-list",
    "Host/McAfeeLinux/rpm-list",
    "Host/OracleVM/rpm-list",
    "Host/RedHat/rpm-list",
    "Host/Slackware/packages",
    "Host/SuSE/rpm-list",
    "Host/XenServer/rpm-list"
  );

check_pat = INJECTION_PATTERN;

installed_package = "";

foreach pkgmgr (distros)
{ 
  pkgs = get_kb_item(pkgmgr);
  if(!isnull(pkgs) && ("suidperl" >< pkgs || "perl-suid" >< pkgs)) 
  {
    match = pregmatch(pattern:"(perl-suid\s*(?:perl)?[^\\|\s]+)", string:pkgs);
    if(!empty_or_null(match) && !empty_or_null(match[1])) installed_package = match[1];
    vuln++;# make it vuln
    break;
  }
}

ret = info_connect();
if (!ret) audit(AUDIT_FN_FAIL, 'ssh_open_connection');

error = NULL;
p_dir = info_send_cmd(cmd:"which perl");
if(!empty_or_null(p_dir))
{ 
  if(p_dir =~ check_pat) exit(0, "Supplied path string contains disallowed characters.");

  cmd = "dirname " + chomp(p_dir);
  p_dir = info_send_cmd(cmd:cmd);
  p_dir = chomp(p_dir);

  error = ssh_cmd_error();
  if(!empty_or_null(error))
  {
    if(error =~ "dirname:\s*missing operand") audit(AUDIT_NOT_INST, "perl");
    else exit(0, "The following error was encountered : "+error);
  } 
 
}
if(empty_or_null(p_dir)) audit(AUDIT_NOT_INST, "perl");
if(p_dir =~ check_pat) exit(0, "Supplied path string contains disallowed characters.");

error = NULL;
cmd = "ls -l " + p_dir + "/sperl*";
lsperl = info_send_cmd(cmd:cmd);
error = ssh_cmd_error();
if (info_t == INFO_SSH)
  ssh_close_connection();

if(!empty_or_null(error))
{
  if(error =~ "No such file or directory") audit(AUDIT_NOT_INST, "suidperl");
  else exit(0, "The following error was encountered : "+error);
}

if(!empty_or_null(lsperl) && lsperl =~ p_dir+"/sperl")
{
  if (lsperl =~ "^.rws")
  {
    pattern = "("+ p_dir + "/sperl.*)\s*$";
    path = pregmatch(pattern:pattern, string:lsperl);
    path = path[1];
    vuln ++;
  }
  else audit(AUDIT_HOST_NOT, "affected. suidperl was found but its setuid bit is not set");
}

if(vuln)
{
  report = 'The remote host has a vulnerable version of suidperl installed: \n';
  if(!empty_or_null(installed_package)) report += '\n  Installed Package : ' + installed_package;
  if(!empty_or_null(path)) report += '\n  Path              : ' + path + '\n';
  security_report_v4(severity:SECURITY_HOLE, extra:report, port:0);
}
else audit(AUDIT_NOT_INST, "suidperl");
