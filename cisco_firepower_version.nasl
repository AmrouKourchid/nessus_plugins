#TRUSTED 559e23905d0200a0cb8aa9e3451e0031d0681c476ca1174134a6472870ffff308469f256e23915cec2e59097453b182da8331b96dd38f7246ba87b19615169bc77d4a43232b99d3882e357b916cb72f1121e420f26c5694cf541a0499ee81b4dcd1b5c41a0c68a34a0d6d7cc9a199533ebe1612ad052b0cd6672e495dc6bf3f63b72093e05471daea6ac1d27b7e4d90cb1fba8893381045dbb84363afb61f31fc9535cfd8700a3713638f05c0b0c6680a6c1b400ba42b19119ba9b6b89036dfea8b95ab1d7f95dc0bd11f7da913e7bba09ef560b55302220a85005ee59277e88a4b32361aff2b6e33a244f25931a0f944945c99dd17e541f97d879d6790cdd9b96d8bc1e47cd6170fe578245f03ea9524ea905c185248b91bafa2e7c8e006b7ed064ca937ca3281ecc73115bc5418c111874bdf7b9b8bcc6f732e5d29d6819ce6bf3b4bbaa66cf1e4bc7cba7456bc61e8f745f6f1d56dd68d6b8fb40db87d2639a2536afe236eea1fd2dd5c883670ba81606c3a45bb5b6501ce6d5dc41883fbb454ec32528c2e8f7d5a71f52e94e1b6bf683d9722d7e48e96ce619105bcd41738827fb71bc56d28009b474b77724094ffa67b2178484913ca331daf02b3f8d6a94d43ac09774fb397eb2917440d599ee8c22b93a9722dea8cedcaf99d541279dbef46d2031c59a4beceaec701b8828908a56a8182e65d5a77c82ce9975714bc2
#TRUST-RSA-SHA256 942893aaa4ce4f258eb9ab38a6413f518d9972b4e7b0eeecb343cab3fbc6a3dcdf72d8f8f1498e49eee6c95014ea77fcf7a485b17b183cfad030f2d37439b338be99b4c51bd8cc96a616c0fe4625fcaa8e9f7cb901e9117963ce9f4e3112b93790567a3b61f51edc3e75566202ec5bbf423bae75fd6414fb3b0b0aa42bd71814a80aa9551e5bb7cd648e982fdd4af99cc2f0b5a4ce8ced0e1193251359304b917f0cd2b9c26db4c6c3b4e24bd4ac81a0ec9c6f4e6d3ddf72d10c6a0352f3b1c3620b72417d9185bd4f9c32fc47a059b4721973108bef85aec7bada1f6bfa54af7a879b6fbdbecbfd8cab4c2526845bde1dde936e4b1f84b37bf607c9eba13ee72999879ae283fbebea0c209f17f0c777a1bae4fc96e72e63faa665a1767c161c6ceee7990aa8ace49a100d43e3c308c3e0f0a3107869e3459a0734be71b4c64fd628ae70490eddcab712df18806b07198be25cd227d5eb1eebee6ff9cbc99dd46f900f544a8e55d61efd4c41dd0c7442d0ff2a3d9cb214bafe50f1e76741d763fbf9783b7ff1549349fedfaf92c22ed2a83a58d835f7959e3e745f7e3170806569f2489b450ce8b05811498d8fe03a38a31bde107320d3d88729f5da7abeec157f983f6193599b2ae125e302b4ce5edbf5a6c15e44119a681057bd9e5317dd346ff72a4a3fcbef15dc55bdfdec960db262c664d005e7799850494adb54fc99f1
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94470);
  script_version("1.39");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_xref(name:"IAVT", value:"0001-T-0550");

  script_name(english:"Cisco Firepower System Detection");
  script_summary(english:"Obtain the version of the remote Cisco Firepower System.");

  script_set_attribute(attribute:"synopsis", value:
"Cisco Firepower System is running on the remote host.");
  script_set_attribute(attribute:"description", value:
"Cisco Firepower System is running on the remote host. Firepower System
is a comprehensive management platform for managing firewalls,
application control, intrusion prevention, URL filtering, and advanced
malware protection.

It was possible to obtain version information for the Firepower System
using SSH.");
  #https://www.cisco.com/c/en/us/products/security/firepower-management-center/index.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2b72c506");
  #https://www.cisco.com/c/en/us/td/docs/security/firepower/roadmap/firepower-roadmap.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ef16908d");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor",value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/02");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:cisco:firepower_management_center");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2004-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_ports("Services/ssh", 22);
  script_require_keys("Host/uname");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('ssh_func.inc');
include('hostlevel_funcs.inc');
include('install_func.inc');
include('spad_log_func.inc');

enable_ssh_wrappers();

function report_and_exit(ver, build, source, vdb_ver, vdb_build, patches_ssh, interrupt_msg)
{
  local_var report, jank_ver;

  jank_ver = ver;
  if (!isnull(build))
    jank_ver += '-' + build;
  replace_kb_item(name:'Host/Cisco/firepower/Version', value:jank_ver);
  replace_kb_item(name:'Host/Cisco/firepower', value:TRUE);

  replace_kb_item(name:'Host/Cisco/firepower_mc', value:TRUE);
  replace_kb_item(name:'Host/Cisco/firepower_mc/version', value:ver);
  replace_kb_item(name:'Host/Cisco/firepower_mc/build', value:build);

  report =
    '\n  Source  : ' + source +
    '\n  Version : ' + jank_ver;    

  if (!isnull(vdb_ver))
  {
    replace_kb_item(name:'Host/Cisco/firepower_mc/vdb_version', value:vdb_ver);
    report = report + '\n  VDB Version : ' + vdb_ver;
  }

  if (!isnull(vdb_build))
  {
    replace_kb_item(name:'Host/Cisco/firepower_mc/vdb_build', value:vdb_build);
    report = report + '\n  VDB Build   : ' + vdb_build;
  }

  if (!empty_or_null(patches_ssh))
  {
    replace_kb_item(name:'Host/Cisco/firepower_mc/patch_history', value:patches_ssh);
    report = report + '\n  Patch History   :\n' + patches_ssh;
  }

  if (!empty_or_null(interrupt_msg))
    report = report + interrupt_msg;

  report += '\n';

  security_report_v4(port:0, extra:report, severity:SECURITY_NOTE);

  exit(0);
}

uname = get_kb_item_or_exit('Host/uname');

# Examples:
#  Linux firepower 3.10.53sf.virtual-26 #1 SMP Mon Feb 22 20:47:53 UTC 2016 x86_64 GNU/Linux
#  Linux am1opd1fp 3.10.45sf.westmere-17 #1 SMP Fri Oct 30 14:59:18 UTC 2015 x86_64 GNU/Linux
#  Linux firepower 3.10.53sf.virtual-53 #1 SMP Wed Nov 23 14:50:49 UTC 2016 x86_64 GNU/Linux
#  Linux Lab-asa5506 3.10.62-ltsi-WR6.0.0.29_standard #1 SMP Thu Nov 9 06:32:13 PST 2017 x86_64 x86_64 x86_64 GNU/Linux
#  Linux fpr-2100.lab.tenablesecurity.com 4.1.21-WR8.0.0.25_standard #1 SMP Tue Apr 16 12:21:06 PDT 2019 x86_64 x86_64 x86_64 GNU/Linux

##
#  If the 'uname' response does not contain 'Linux', this is probably not Cisco Firepower
#  Look for other Cisco/Sourcefire indicators, but do not exit if they are not found
##
if ( 'Linux' >!< uname)
{
  spad_log(message:'Linux string not matched in uname: ' + uname);
  audit(AUDIT_OS_NOT, 'Cisco Firepower');
}
else if ('sf' >!< uname &&
         'WR' >!< uname &&
	 '_standard' >!< uname)
{
  spad_log(message:'Firepower characteristics not matched in uname: ' + uname);
}

##
#  Additional (more reliable) verification
##
is_firepower = FALSE;

redhat_rel = get_kb_item('Host/etc/redhat-release');
slackware_rel = get_kb_item('Host/etc/slackware-version');

if ('Sourcefire Linux' >< redhat_rel ||
    'Fire Linux' >< redhat_rel ||
    'Sourcefire Linux' >< slackware_rel ||
    'Fire Linux' >< slackware_rel)
{
  spad_log(message:'Firepower matched in redhat_rel or slackware_rel');
  is_firepower = TRUE;
}

patches_ssh = get_kb_item('Host/Cisco/FTD_CLI/1/rpm -qa --last');
if (!empty_or_null(patches_ssh) &&
    'Sourcefire_Product_Family' >< patches_ssh)
{
  spad_log(message:'Firepower matched in rpm -qa --last output');
  is_firepower = TRUE;
}    

if (!is_firepower)
{
  spad_log(message:'Firepower characteristics unmatched');
  audit(AUDIT_OS_NOT, 'Cisco Firepower');
}


##
#  Firepower confirmed at this point
##
firepower_ssh = get_kb_item('Host/Cisco/os-release');
model_ssh = get_kb_item('Host/Cisco/model_conf');
vdb_ssh = get_kb_item('Host/Cisco/vdb_conf');


if (empty_or_null(patches_ssh) ||
    empty_or_null(firepower_ssh) ||
    empty_or_null(model_ssh) ||
    empty_or_null(vdb_ssh))
{

  sock_g = ssh_open_connection();
  if (! sock_g)
    audit(AUDIT_FN_FAIL, 'ssh_open_connection');

  if (empty_or_null(patches_ssh))
  {
    spad_log(message:'Executing rpm -qa --last');
    sleep(1);
    patches_ssh = ssh_cmd(cmd:'rpm -qa --last');
  }

  if (empty_or_null(firepower_ssh))
  {
    spad_log(message:'Executing cat /etc/os.conf');
    sleep(1);
    firepower_ssh = ssh_cmd(cmd:'cat /etc/os.conf');
  }
  if (empty_or_null(model_ssh))
  {
    spad_log(message:'Executing cat /etc/sf/model.conf');
    sleep(1);
    model_ssh = ssh_cmd(cmd:'cat /etc/sf/model.conf');
  }
  if (empty_or_null(vdb_ssh))
  {
    spad_log(message:'Executing cat /etc/sf/.versiondb/vdb.conf');
    sleep(1);
    vdb_ssh = ssh_cmd(cmd:'cat /etc/sf/.versiondb/vdb.conf');
  }
  ssh_close_connection();
}

# Package enumeraiton is prone to timeouts, so check if the command was interrupted
if (ssh_cmd_interrupted())
{
  interrupt_msg = '\nSSH command interrupted due to timeout or error:\n' + cmd + '\n';
  interrupt_msg += '\nPlugins will be unable to properly check installed hotfixes.\n';
}
# in case we see other 'MODEL's
# MODEL="Cisco Firepower Management Center for VMWare" -> MODEL_TYPE=CONSOLE
spad_log(message:'cat /etc/os.conf:\n' + firepower_ssh + '\n\n');
spad_log(message:'cat /etc/sf/model.conf:\n' + model_ssh + '\n\n');
spad_log(message:'cat /etc/sf/.versiondb/vdb.conf:\n' + vdb_ssh + '\n\n');
spad_log(message:'rpm -qa --last:\n' + patches_ssh + '\n\n');

# Validate that we got packages and not an error by looking for a date like "Mon Apr " from the --last, set to NULL if
# not so that this won't be reported
if (patches_ssh !~ "[A-Z][a-z]{2} [A-Z][a-z]{2} ")
{
  spad_log(message:'No date in result of rpm -qa --last, setting patches_ssh to NULL');
  patches_ssh = NULL;
}

vdb_version = pregmatch(string:vdb_ssh, pattern:"CURRENT_VERSION=([0-9.]+)\W");
if (!empty_or_null(vdb_version) && !empty_or_null(vdb_version[1]))
  vdb_version = vdb_version[1];
else
  vdb_version = NULL;

vdb_build = pregmatch(string:vdb_ssh, pattern:"CURRENT_BUILD=([0-9]+)\W");
if (!empty_or_null(vdb_build) && !empty_or_null(vdb_build[1]))
  vdb_build = vdb_build[1];
else
  vdb_build = NULL;

if ('SWVERSION' >< model_ssh && 'SWBUILD' >< model_ssh)
{
  version = pregmatch(string:model_ssh, pattern:"SWVERSION=([0-9][0-9.]+)\s*([\r\n]|$)");

  if (!isnull(version))
  {
    version = version[1];
    build = pregmatch(string:model_ssh, pattern:"SWBUILD=([0-9]+)\s*([\r\n]|$)");
    if(!isnull(build))
      build = build[1];    
    report_and_exit(ver:version, build:build, source:'SSH', vdb_ver:vdb_version, vdb_build:vdb_build, patches_ssh:patches_ssh, interrupt_msg:interrupt_msg);
  }
}
else if (
  'OSVERSION' >< firepower_ssh &&
  'OSBUILD' >< firepower_ssh
)
{
  version = pregmatch(string:firepower_ssh, pattern:"OSVERSION=([0-9][0-9.]+)\s*([\r\n]|$)");

  if (!isnull(version))
  {
    version = version[1];
    build = pregmatch(string:firepower_ssh, pattern:"OSBUILD=([0-9]+)\s*([\r\n]|$)");
    if(!isnull(build))
      build = build[1];
    report_and_exit(ver:version, build:build, source:'SSH', vdb_ver:vdb_version, vdb_build:vdb_build, patches_ssh:patches_ssh, interrupt_msg:interrupt_msg);
  }
}
audit(AUDIT_UNKNOWN_DEVICE_VER, 'Cisco Firepower');
