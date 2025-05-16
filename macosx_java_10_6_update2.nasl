#TRUSTED 49fe101726add108232edc6470d650bccb5c52caff9351fe2781ce7faf4ce897af19513b394e69f59c8305644f0d12b7f449f5867d0f4b15db0939b28a1344e3597f207e4e61f1fa55bc990c3cddf0080e2227b9c3d68f2b51922de384dd6b116390a9825c5bee8a6f87024c1c226efc8251692d1ef2b853f12e111394f1255767a2e5ab5b27382b782c1aa6470c9f60ef68ffadf1dbb1c58fd23b70ed9da6832a28d3839aa1219f9b1709e0cc630f3d851ad24bfaab147d84ee5e48d5e73b7af06cb48947612cd1dab5426e4319c452e83d8a293a27855499bdb63458dedfc3d37654a1dfb92978fba24cf0eb5c3df371750b1cd70544ff2133b7f3f61a76605224209f0fccc089be24b4b927f8594ea874196fa6045e1c2f1f32b9b846b62790d4ea674d9bf2c15c48a47dba5620c2650e80ff7ddbdcedf7e7408fa5d5689a8e24d2a3957f1841a7d6d5b5bbb8fd6a6f899d9e64182a8a33c0ec81f1a5f16c5a28cd737020f391a5bd5262f36e7c9913682e1e44e9c60d562152b28c9bfa000037becd0a0d926b2c5173f6d4fee40d226c79f2be73f311d45be9e7f1289de126a4beafea618022b7d10784a56ddb984960ef75579d327118a6a71aacdad32d43dc4a92503a33add582c3e959eb978130909b83c711688fdf832c8739f8a815064353f93422d19d2d823507e4c1b761787484d7686c71c6ddde8d1b0841d982
#TRUST-RSA-SHA256 2dbe56df53ca8c1cf05cbf49234f935bc92faa7748b14798c4ae3aa0eb824844e97c45326b38b01ba6b6ee35c2b02e44f7364f9b99e80578f6a55d0ec1fd4c058c8ac6ff9dbbc94513629c0985d135ff2503ea6c8e7d4583c0f5c2e56a6ffd939738868b6b75b6d698b713002600079141db04b6ea9293ce7df4cf18ceee26ef64fc08a53e5e0404f472ca20717d9f36e1a13e8b9b09b98d949a1d58ac8fbdef62f183a59fcb453922ec88f583509a40d2a270e699fea451fb5f60b09f6220260bf8003b0f09ee8d99562caf2b106ddac87a9525293dfde17ed585e3249c859548cdf28f34659cd2f91c61d212bdd370434a144e7cd645a618c64b764451b50c7ead2bdee39825ae4ed490463421beb30f690f4478fa0fd27fdc319b7649f4a14a89733e49100411edec3e3863194111df1ea5a02f0d8953a3c5ddd2328585f2d84f3126a2bceb25267093b50eda09a2f8f7a0617bdd86a46de4f8410cbf40dd5a21439280d72f6a56daeac7a73bb140c2bb7ddffe63ee5a7a67b9058901ece86f6a963bb51f1b32532a2de1c663275d0c14af2168e88ecc25ad846d9c71839c7ec4ef935df2e5edf288740ddcda4cb2dacfe0673d5c6acdbe6eab295db77e627f3f6c58d2ba975ef81f7d3f65adba9ea3bb3faab3f18699ffc4dc95ea52f45d5c23daf63d0adcf086ddcf8ad33afdf3693d97b7b9b2cb2bede2ee93d1565e22
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(46674);
  script_version("1.26");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/24");

  script_cve_id(
    "CVE-2009-1105",
    "CVE-2009-3555",
    "CVE-2009-3910",
    "CVE-2010-0082",
    "CVE-2010-0084",
    "CVE-2010-0085",
    "CVE-2010-0087",
    "CVE-2010-0088",
    "CVE-2010-0089",
    "CVE-2010-0090",
    "CVE-2010-0091",
    "CVE-2010-0092",
    "CVE-2010-0093",
    "CVE-2010-0094",
    "CVE-2010-0095",
    "CVE-2010-0538",
    "CVE-2010-0539",
    "CVE-2010-0837",
    "CVE-2010-0838",
    "CVE-2010-0840",
    "CVE-2010-0841",
    "CVE-2010-0842",
    "CVE-2010-0843",
    "CVE-2010-0844",
    "CVE-2010-0846",
    "CVE-2010-0847",
    "CVE-2010-0848",
    "CVE-2010-0849",
    "CVE-2010-0886",
    "CVE-2010-0887"
  );
  script_bugtraq_id(
    34240,
    36935,
    39069,
    39073,
    39078,
    39492,
    40238,
    40240
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/15");

  script_name(english:"Mac OS X : Java for Mac OS X 10.6 Update 2");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a version of Java that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host is running a version of Java for Mac OS X
10.6 that is missing Update 2.

The remote version of this software contains several security
vulnerabilities, including some that may allow untrusted Java applets
to obtain elevated privileges and lead to execution of arbitrary code
with the privileges of the current user.");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT4171");
  # http://lists.apple.com/archives/security-announce/2010/May/msg00001.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1aac62be");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Java for Mac OS X 10.6 Update 2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2010-0887");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Sun Java Web Start Plugin Command Line Argument Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");
  script_cwe_id(310);

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/05/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/05/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/05/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2010-2024 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/MacOSX/packages");

  exit(0);
}


include("misc_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");



enable_ssh_wrappers();

function exec(cmd)
{
  local_var ret, buf;

  if (islocalhost())
    buf = pread_wrapper(cmd:"/bin/bash", argv:make_list("bash", "-c", cmd));
  else
  {
    ret = info_connect();
    if (!ret) exit(1, "info_connect() failed.");
    buf = info_send_cmd(cmd:cmd);
    if (info_t == INFO_SSH)
      ssh_close_connection();
  }
  if (buf !~ "^[0-9]") exit(1, "Failed to get the version - '"+buf+"'.");

  buf = chomp(buf);
  return buf;
}


packages = get_kb_item("Host/MacOSX/packages");
if (!packages) exit(1, "The 'Host/MacOSX/packages' KB item is missing.");

uname = get_kb_item("Host/uname");
if (!uname) exit(1, "The 'Host/uname' KB item is missing.");

# Mac OS X 10.6 only.
if (!egrep(pattern:"Darwin.* 10\.", string:uname)) exit(0, "The remote Mac is not running Mac OS X 10.6 and thus is not affected.");

plist = "/System/Library/Frameworks/JavaVM.framework/Versions/A/Resources/version.plist";
cmd =
  'cat ' + plist + ' | ' +
  'grep -A 1 CFBundleVersion | ' +
  'tail -n 1 | ' +
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
version = exec(cmd:cmd);
if (!strlen(version)) exit(1, "Can't get version info from '"+plist+"'.");

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

# Fixed in version 13.2.0.
if (
  ver[0] < 13 ||
  (ver[0] == 13 && ver[1] < 2)
)
{
  gs_opt = get_kb_item("global_settings/report_verbosity");
  if (gs_opt && gs_opt != 'Quiet')
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 13.2.0\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else exit(0, "The remote host is not affected since JavaVM Framework version "+version+" is installed.");
