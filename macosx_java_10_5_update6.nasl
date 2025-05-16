#TRUSTED 7cd12e4ac0f012d7dd15e0e0bfa69b66dda84fe69db32d71a50bca953e7d69f7f0d1325c256da16c0f62e21607b2eabf711bd79b38270a62c9e015650f0e2f88a73ab59d4b73661cacae29ffde366688f8dcc163edf938eca1be238ebdfcf130a165dd084ebcccd40cd368fb004e48f06001499bb246d08872a3fe9675ecde70ea72bc5fa8be1cbee263c3d414d27d78c4349435922ed7d86a680f0563fac6e2e63971e3cf5839cf589e358ed6ba3e0fa670fd4d3bd933faab5fe87d849da60ef7da2579b38aee6f1299e2e92dc3f671c5dcc3dcb6651628b657633d998ceff76bd847689ac2869625dfc5538ddf532acef152de4774e18d505f93e450dac012ca19adfe5894376adcdd5334c640d9b021df3068689b3abbe92b6e6e1e92ed9621c6536eb40118194e898100146ef06d7eeea8fc9f54e6647d4710e9e23d7a05fe0bbaaf93b7bb139a66976e6afdad84d7b0569f8c7c088a5941e8691dbb03fd0c79b8ea197a30c2fe78b153a11b0a907d3b4191c3d1501d2a1ce4a3b9d545a006cd879ddb37e9caf1e5016a6b904914d5faa09fcc2b208e8b7daa0447f77cce6514a9455a38b32b83db83e9615ba7b9512751a4a6038a628f2bd2b7b0e6713550a3a54059d5c3031bb92af70eec6aefc394f9bd1243bfbc563dd635863a3b9a01173b77b38bdba4040be4e00489408c64962de2317140d1083cc77df1a85dde
#TRUST-RSA-SHA256 077d09f212430d969066a8f8cbbe15003faeb58b5f89d9d2039d4a01f2fca2baae465a1beedc0e27ad6ad59f26119ae7ff766c3517a0b3b4f48339cbe5e3af42cc57195242a6e7ad5998c3b7a69942b0fa5012e22e8a20c71d1509bded691da128378dc04294d28002e68c68c9cd1aae38db335aefbc9a2461b89a2fb64dcea229ef580ddc82fe59c7f3fac09c6c080f46d6511532f78e874ce6f4ab5f711b31e3056bb0f1ec3485a42e74c5801dbd58bc8e9c7e11fad568842f58dee53b52511f736cca779fa14f7ebd2ad20b7818f3c837901af9fe452cae5868ed6a8682e03bc2f2a63299ca3f017f3810ab63d0b9920dc615feab484ce5379e2b9d2b027d7dfb989e705ff0667791eaf97a3ef259928d3ad9703dfbcbd5adf5e78dbfe02e1be8d545ed3f6258cca5bff46630bf637695e24373dadd654666f2cfd05533806832d4e59fb713e7150e75cc661aaad7fea9aea26ef8505e1edeb1859207100bdf4872d82be6aee1299c173a31789edc79a590a8575338665e7881bca6141567adf95aff290672dffbbdd5935ad1fd2c336680fc6e0c2a8e2a49c2dde358b7d0f0e76cc66c9680ccef5e1096ac26e470dcc5ff3c4256e38d72f9b7494420af272cec3a5dffef3af7ac1dbcde82cddab550f87e644889d2dd71799ec2e22a21dd03311c272973132bdc0e08ebe3723e173209ebb1aeb35bc84d030516d2fc30df
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(43002);
  script_version("1.23");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/24");

  script_cve_id(
    "CVE-2009-2843",
    "CVE-2009-3728",
    "CVE-2009-3865",
    "CVE-2009-3866",
    "CVE-2009-3867",
    "CVE-2009-3868",
    "CVE-2009-3869",
    "CVE-2009-3871",
    "CVE-2009-3872",
    "CVE-2009-3873",
    "CVE-2009-3874",
    "CVE-2009-3875",
    "CVE-2009-3877",
    "CVE-2009-3884"
  );
  script_bugtraq_id(36881, 37206);

  script_name(english:"Mac OS X : Java for Mac OS X 10.5 Update 6");
  script_summary(english:"Checks version of the JavaVM framework");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has a version of Java that is affected by multiple
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Mac OS X host is running a version of Java for Mac OS X
10.5 that is missing Update 6.

The remote version of this software contains several security
vulnerabilities, including some that may allow untrusted Java applets
to obtain elevated privileges and lead to execution of arbitrary code
with the privileges of the current user."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.apple.com/kb/HT3970"
  );
  # http://lists.apple.com/archives/security-announce/2009/Dec/msg00001.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?be282f4f"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.securityfocus.com/advisories/18433"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Java for Mac OS X 10.5 Update 6 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2009-3874");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Sun Java JRE AWT setDiffICM Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
script_cwe_id(310);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/12/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/12/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2009-2024 Tenable Network Security, Inc.");

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

# Mac OS X 10.5 only.
if (!egrep(pattern:"Darwin.* 9\.", string:uname)) exit(0, "The remote Mac is not running Mac OS X 10.5 and thus is not affected.");

plist = "/System/Library/Frameworks/JavaVM.framework/Versions/A/Resources/version.plist";
cmd = string(
  "cat ", plist, " | ",
  "grep -A 1 CFBundleVersion | ",
  "tail -n 1 | ",
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\''
);
version = exec(cmd:cmd);
if (!strlen(version)) exit(1, "Can't get version info from '"+plist+"'.");

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

# Fixed in version 12.5.0.
if (
  ver[0] < 12 ||
  (ver[0] == 12 && ver[1] < 5)
)
{
  gs_opt = get_kb_item("global_settings/report_verbosity");
  if (gs_opt && gs_opt != 'Quiet')
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 12.5.0\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else exit(0, "The remote host is not affected since JavaVM Framework version "+version+" is installed.");
