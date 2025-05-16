#TRUSTED 7d7689e3ba892990869c1a56f29b9f8e7de20f644940d93c83bdc25b4f5941e050a246fcb2ca0ddeabe0655a6af2e17b04e38f750836765e320d54d20198de54db5206b5b26b3cc890ac0e5528032c65d1cba502eb1e8db86b00e13ef6935f974bc0e42b862612fdd56f28346e8a4ff08b6bcc0f8ef21c3eb4ee4b5d777e41396355c086b016743c0f35c5048b6abef4ac64ef19305e7e023b805b2e25edb64bca5628725615a998ebb88489e4d90906d31d54a949fba7c35da2eba932d5177c4fdfdf02d561fc079077d3a303d5787b4e2bf1cc91c070afdee06c9c9bf48144845b39f42ee089fa3432682f018b1d4960f681754c13874afa0a97a877ad8c445e7050c2c164b8313809d5df88620626edfcb7f275a510915963fd6202ebeb708e45173938109b6eaebf2b0370a9950023d7879c9b4d47444375cec5a45d47d532b7a80251394d3387085822e789d240b73290be16547c2bd3beb4e45f0bd72319fbe0b14bab199845c0f98e2fec388469fcde64d4abceb42e1e436c6320c6c744ce9d8655b4f64b610d00cdc809dc69010e7eac5ebbd9c3f3ed63b95cc67fb34c5e7f12df5b680de11f7a784d61ce761b6d4f53b519089fb832718170460946551772871dcf9c7cf3d4c7e452c29e152d05bc05ef87ceccea54ad6dd021f64704b71429f133b1211ba3e6fe6b9e11f59fe0d0833fe6dd50e10987e49bdc9b22
#TRUST-RSA-SHA256 7a062b125a8fd1636d3267d50cf70317ee833a4b25be36f1f629cc305a0962665a659b9c4476450b3e7418ffee2a8487df8b132b5ff032143913edfcee8ecc102e5e91fa31618f9fba6c99e0f3980437b9a27cc2d31e034a6befb212e891ce2345cd5436971191262520695f328857b087f79f39bf9e68fc81b6b880b95fec5123d9b64b3aeb639a11ea269334464955927a949bdc9a76fa51802b0ae6dbf498d6e6d4504bfe467914aeaeaa0cc0c037ab143c8757235f3a8b22d6ab671e5cd51fbeec4d542865dd5ec12a724e87c8c664cc1053dbd76547183a532d8da35eb564edf09055dee57e57d2ac85c3d38428a6778b5b4448b960aea42621c9b3421991c3498899be048c2f887da7838aaac544230981958a9845a0fc3a125b5a59d3e2d570431b006d3e777283b9865bef6dbd5cf8a3f50c43ec91996b5dc98fb4334c78c569a7f40e95e9aa854034f3d700e3b4b79d595f557342053011e837250b47cf9e6fabf7bbf69ad14aa891977c3d42d73aa707f8f0a6bfc406e2115dab2a38921dbed46fee88110f876726c4ad94bc0bfd3999f43623acb45b7706969fdeb7ac7382be7161053f0b0bc2abcc0b4563afdc94ea39a32f426f8111f18d8fe974e633d25e48a906002d30889aeb139469b8ebd175f3ad67865c53eb4856e9ef7771a599296557348963d5fc61c734d4a0f06a6272cb22933c67ad6880e82bc5
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69420);
  script_version("1.25");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/24");

  script_cve_id("CVE-2008-1369");
  script_xref(name:"IAVA", value:"2008-A-0025-S");

  script_name(english:"Sun SPARC Enterprise T5120 and T5220 Default Configuration Root Command Execution");
  script_summary(english:"Check for the configuration of the SPARC Enterprise Image");

  script_set_attribute(attribute:"synopsis", value:
"The remote Solaris host has a misconfigured SSH server.");
  script_set_attribute(attribute:"description", value:
"The remote Sun SPARC Enterprise Server has been mistakenly shipped with
factory settings in the pre-installed Solaris 10 image which configures
the remote SSH server insecurely. As a result, local or remote users may
leverage these misconfigurations to execute arbitrary commands with the
privileges of the root (uid 0) user.");
  script_set_attribute(attribute:"see_also", value:"https://download.oracle.com/sunalerts/1018965.1.html");
  script_set_attribute(attribute:"solution", value:
"Follow the steps in the workaround section of the advisory above");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2008-1369");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(264);

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/03/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/03/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain a shell remotely");

  script_copyright(english:"This script is Copyright (C) 2013-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/uname", "Host/local_checks_enabled");

  exit(0);
}

include('ssh_lib.inc');
include('local_detection_nix.inc');

get_kb_item_or_exit('Host/local_checks_enabled');

enable_ssh_wrappers();

var buf = NULL;
var cmd_template = NULL;
var ret = NULL;
var uname = NULL;
var report = NULL;
var report_data = {
  'default_login_contains' : FALSE,
  'sshd_contains'          : FALSE,
  'dot_profile_contains'   : FALSE
  };

uname = get_kb_item_or_exit('Host/uname');
if ('SunOS' >!< uname)
  audit(AUDIT_OS_NOT, 'Solaris');

ret = info_connect(exit_on_fail:TRUE);
if (!ret)
  audit(AUDIT_SVC_FAIL, 'SSH', sshlib::kb_ssh_transport());

# Get full path to grep util
if (!ldnix::grep_supported())
  audit(AUDIT_NOT_INST, 'grep');

grep_path = ldnix::get_command_path(command:"grep");

if (!empty_or_null(grep_path))
  grep_path = grep_path[0];
else
  audit(AUDIT_FN_FAIL, 'ldnix::get_command_path(command:"grep")', NULL);

#
# https://download.oracle.com/sunalerts/1018965.1.html
#
if (ldnix::file_exists(file:'/etc/default/login'))
  buf = ldnix::run_cmd_template_wrapper(
    template: '$1$ CONSOLE= /etc/default/login',
    args: [grep_path]);

if (!empty_or_null(buf))
  report_data['default_login_contains'] = buf;

if ('#CONSOLE=/dev/console' >!< buf) {
  ssh_close_connection();
  audit(AUDIT_HOST_NOT, 'affected');
}

buf = NULL;

if(ldnix::file_exists(file:'/etc/ssh/sshd_config'))
  buf = ldnix::run_cmd_template_wrapper(
    template: '$1$ \'^PermitRootLogin \\+yes\' /etc/ssh/sshd_config',
    args: [grep_path]);

if (!empty_or_null(buf))
 report_data['sshd_contains'] = buf;

if ('PermitRootLogin yes' >!< buf) {
  ssh_close_connection();
  audit(AUDIT_HOST_NOT, 'affected');
}

buf = NULL;

if (ldnix::file_exists(file:'/.profile'))
  buf = ldnix::run_cmd_template_wrapper(
    template: '$1$ "PS1\\|LOGDIR" /.profile',
    args: [grep_path]);

ssh_close_connection();

if (!empty_or_null(buf))
  report_data['dot_profile_contains'] = buf;

if ('PS1=\'ROOT>\'' >!< buf ||
     'LOGDIR=\'/export/home/utslog\'' >!< buf)
  audit(AUDIT_HOST_NOT, 'affected');

# Require all three in order to be marked vuln
if (!report_data['default_login_contains'] ||
  !report_data['sshd_contains'] ||
  !report_data['dot_profile_contains']
)
  audit(AUDIT_HOST_NOT, 'affected');

report =
  '\nNessus was able to detect the vulnerability by locating the ' +
  '\nfollowing items :' +
  '\n' +
  '\nIn file /etc/default/login : \n' + report_data['default_login_contains'] +
  '\nIn file /etc/ssh/sshd_config : \n' + report_data['sshd_contains'] +
  '\nIn file /.profile : \n' + report_data['dot_profile_contains'] +
  '\n';

security_report_v4(port:0, severity:SECURITY_HOLE, extra:report);
exit(0);

