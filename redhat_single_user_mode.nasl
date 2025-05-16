#TRUSTED 33ba697aca916b177dbe0ef1686b454fdba75ad5df772ed8a9060478617e1696dc57e1f2e7fb19c5c26fc73d36ecf4dd5a0b1baab2eaa1fb417dbc5a61a66ea60faeba41f735301166a22457ee2490d5c6e2a71559de53c7e4eb92ecc6b77c12f86492ede2f148453a6dd13c415851323fb269a962a20ef33d8aa4921a6cfea11aafbde5615f0618451eacc70e443ce4186248f6099d2d925540aa8d92bad11dc4a8d21d3fc54d6166274a452cfa4bb38c47ced86433bf60e77940e132748551087ce3d6d82c8d2c77d77d3f8b2b305cc50e7f5cecb63c454131eb51ca83da7404dd98b3dec215eb31a9998e74d6e933f1704ff31f1aa86f70ed6333174222fc10f51454adb036ee7937b8e6fd3ea0b4e5e32be9af3ac90533baf48a5ddd64a3a78e4ea59419e082929d0d0dc955e35bbcae3f406386e59616f3c626ae6cad8605d468714557022a91734745496cdebbcc7baed154c128ffd62c31f0c216d493dc2ee5283016757b49198ce955a36a1da9f910e98044488c0242c8597a39038a2342a2cf314036b7a5c1454b968c2c41bba3e2cc79316c30b10a960e0fdc6111ed1efaeb6889581b312e7ecf78f4171f6d7e6dd28da474f151ecf4c93bf4bdfe29f0bf73bbab879fc4c9f5db7ec7116cc798209c08f1fe6d1f9f62fe88ce6bf467b3aad40ef2e779b24cdbfaca99e3ce5951279e0e4bdccd519ea246e3e986f0
#TRUST-RSA-SHA256 0987c53416a6d4e4bba63ec829baaef432f89400a309e18363b126a88e51a53b9f943ebd879c1dd7ec3aa06095389279ff8670b6b7ca8faacb3c4b1229a44bbea817fc4bcb9af72599fa169dca2953377b9a8340a85f592fff605ba8e2b524b8cdb6fad07a48dd0b961a7118536b41799c79dee9ee1f85bfdd24311a7d558b4bb7275deb578954362d1d3794cb92d1d37a01cbe54c4e53da6a659590ad296b1592da28f99336692e78e15a4cc3460081bd84706082f6d1084ae9380e926173d85f304c93a32fe860e9e28f3042f4d833296847a7b18caa38b0b8cbf1d886057097a99c9a97948ecb46feafcbd31d32d005e7cec4a8615dfac757eac00ea280d8061caf1e8dec6873e87af059b641e055e40628c95cbf41edac32ac61b3977879e86a4ac2590975598caba976d975f3ab22ccf70e858c066a1ef4fe1241eb98e5c07b6bf6238e5d2ab5f80a5329f4f0608e595eca9b45c032d17bfb60549b9abd5eec32942e3166520f18f00a3296b7d4c66fd3797a3b62756c0ad2b7b82e3720fa9522acd73cc97d4a305128e3c3dfa34b65e8d8180ab98072c8527653894d36102ccf729560be9e2f33161245fc3b2b6352abed32f65394a892fb488c1e9327bcd565b8a0d278cf557be0748cb8bd50f59f2dcee504d6dec06e9eb9624f141fe7487a45a9a788d6046bda875b7860f39074baa45a91d04676420b0bf9a84a62

#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(105412);
 script_version("1.9");
 script_cve_id("CVE-2000-0219");
 script_bugtraq_id(1005);

 script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

 script_name(english:"Red Hat Single User Mode");
 script_summary(english:"Checks for authorization with single user mode.");

 script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host can be accessed via single user mode without root password.");
 script_set_attribute(attribute:"description", value:
"The remote Red Hat system does not have authorization for single user mode enabled.
An attacker with physical access can enter single user mode with root privileges via the
LILO or GRUB boot menu.");
 #https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/6/html/deployment_guide/sec-single-user_mode
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?14b14125");
 script_set_attribute(attribute:"solution", value:
"Edit '/etc/sysconfig/init' and set the 'SINGLE' configuration value to 'sulogin'.");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/21");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:linux");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2018-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
 script_family(english:"Red Hat Local Security Checks");

 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/local_checks_enabled", "Host/RedHat/release");

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("ssh_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");

enable_ssh_wrappers();

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

redhat_release = get_kb_item("Host/RedHat/release");
if (isnull(redhat_release) || "Red Hat" >!< redhat_release) audit(AUDIT_OS_NOT, "Red Hat");
if ("Red Hat Enterprise Linux" >< redhat_release) audit(AUDIT_INST_VER_NOT_VULN, "Red Hat Enterprise Linux");

os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:redhat_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");


os_ver = os_ver[1];
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (islocalhost())
{
  if (!defined_func("pread")) exit(1, "'pread()' is not defined.");
  info_t = INFO_LOCAL;
}
else
{
  info_t = INFO_SSH;
  ret = ssh_open_connection();
  if (!ret) exit(1, "Failed to open an SSH connection.");
}

vuln = FALSE;
res1 = info_send_cmd(cmd:"cat /etc/sysconfig/init | grep SINGLE");

if (res1 =~ '^SINGLE=/sbin/sushell')
  vuln = TRUE;

if(vuln)
{
  report = "According to '/etc/sysconfig/init' it is possible to gain root access (without password)";
  report += ' in single user mode:\n  ' + res1;
  security_report_v4(severity:SECURITY_HOLE, extra:report, port:0);
}
else
  audit(AUDIT_HOST_NOT, "affected");
