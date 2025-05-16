#TRUSTED ab9ef9223df023b0295db84a54ad7399eaf62fa6f60aeed7154391caa605f9f227084687da35a71b1fd2993d573f9344db04f7f9fc9652dc01c6e44ab550abf695108d423c663fe4574e3b3cff8baa96c258cd4d7f2b41d25a6b3d9605d6f7711b1fe89e59f94772b2bc21336b7718db320dc6284d82e6ba0172544f7efe98b6c703205cd31e0f3bff1bde093ad1b3ebb7714b20444342f4208a805bb64cd1ae57fa3b6233137d53bf80d1acd0f59a8c1b1c9ec50bbab09388a14834356802a8aca40e5a18082b5c26c1b33fec1a6cbea17580b4c88e379596ac30de9d66c2d21b90a0613a2d61257f42e565449cdf796792de041bd19f4115338def34e425fdb5195a431963ba53a7cda9505c6fc01a6db90fc3f5cd337cdc2fe45252df3c7924e0f771a35f53792a86444b4d627c451064f1586ad987380e663a0391cb1f520088c173e40a7d7778e3007a232ae744d2fd081b912fc07b0dbfa1cda32c12868296948c6606aa0ca491995493a6ba94f19bd95f4c088ab8e0e9c06c4a155cdcb271a8fdd674300e90d64511d08cab8e207462847be3d069a5ddf590be0954957790ffd3f4813b1e90b5373c20863aa21d6545cb871bf0d3b4769392b09c7cf6e324094212d6edca5c7d69619bcce3a984b50f8bb27cec6e670a9c2d795757d44ed93fb79bc60ce93528272b50372ce4d0ff962fcf6673cac0d8653480038e0c
#TRUST-RSA-SHA256 41dbb3a3ed0f2bd30f4a171c95800efde03a3cab9540871590140d15c71a14454344b21dbe6029c33b84e54fe11dc763d732ed2eac7630cb73348891574c5fa2b91bfea234928b9acb624505c36921c05167a6fa0c000e4d72462eee8c59ab58682d2512a53a68e1e781bd3c7b5fbe3428bc6d896af0a3eddaa544753ac85fb62614b1a2ddff8f4d0ef15d13ce35fb355c06eda511ffaf8bdf938c09e493c9b32ee9e81cbcb4e6100be5bde6988de16e4e20c81a47d4a4cc904d6d0c8ff9f536766d2d67f62a2deb7c2876cbb95ed41ba9d29de4add895c9d7525390963b2f159448c8e786b2a53bee18010374cec80293a1c25e1c23dd3268dc0bdccea6ced394b32c791eeb4633066b1afb1a41480429d55f532797169bf8e853cd96f3d0400cbb4ed7231259c2e85b0e0fad5af97d68e1b80d47ad3b6720a7d1e09c4c138cc13b10ba6f36c7f949f2a7ec0aa0806b75f5dd4c576cf79b222470fe7a01938feaa6ad080250892ca08732134833bf7e1eee7a18a6bb7c18ea3ba53de680ea6bcff21a3354fc283362c3caeb68ac543f3372447565f642cccdf23e34d290d75df7e85f46c8cb3cdff425814b2b3ed8969e38fd52e8b08bda3b8df634dbd6c6f36edd06f1f0b9c5cc754f6c9bad8564f84c961c5411a8022bfbc03663f6baa64ed98df0fbffd0160878197f2d9c1411589124153b619418286143326f509df8e9
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(52588);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/24");

  script_cve_id(
    "CVE-2010-4422",
    "CVE-2010-4447",
    "CVE-2010-4448",
    "CVE-2010-4450",
    "CVE-2010-4454",
    "CVE-2010-4462",
    "CVE-2010-4463",
    "CVE-2010-4465",
    "CVE-2010-4467",
    "CVE-2010-4468",
    "CVE-2010-4469",
    "CVE-2010-4470",
    "CVE-2010-4471",
    "CVE-2010-4472",
    "CVE-2010-4473",
    "CVE-2010-4476"
  );
  script_bugtraq_id(
    46091,
    46386,
    46387,
    46391,
    46393,
    46394,
    46395,
    46397,
    46398,
    46399,
    46400,
    46402,
    46403,
    46404,
    46406,
    46409
  );

  script_name(english:"Mac OS X : Java for Mac OS X 10.6 Update 4");
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
10.6 that is missing Update 4.  As such, it is affected by several
security vulnerabilities, the most serious of which may allow an
untrusted Java applet to execute arbitrary code with the privileges of
the current user outside the Java sandbox."
  );
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT4562");
  # http://lists.apple.com/archives/security-announce/2011/Mar/msg00001.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?914a9dd8");
  script_set_attribute(attribute:"solution", value:"Upgrade to Java for Mac OS X 10.6 Update 4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2010-4473");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/02/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2011-2024 Tenable Network Security, Inc.");

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
  return buf;
}


packages = get_kb_item("Host/MacOSX/packages");
if (!packages) exit(0, "The 'Host/MacOSX/packages' KB item is missing.");

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
if (!strlen(version)) exit(1, "Failed to get the version of the JavaVM Framework.");

version = chomp(version);
if (!ereg(pattern:"^[0-9]+\.", string:version)) exit(1, "The JavaVM Framework version does not appear to be numeric ("+version+").");

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

# Fixed in version 13.4.0.
if (
  ver[0] < 13 ||
  (ver[0] == 13 && ver[1] < 4)
)
{
  gs_opt = get_kb_item("global_settings/report_verbosity");
  if (gs_opt && gs_opt != 'Quiet')
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 13.4.0\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else exit(0, "The remote host is not affected since JavaVM Framework version "+version+" is installed.");
