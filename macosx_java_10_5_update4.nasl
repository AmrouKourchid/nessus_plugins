#TRUSTED 4fa7b70031ab6b683b8aed3d647e1249578f3dc847a7dde61889a6023ab90572a47f92c35db948025b52630a7f34d7b5e42ee8ad9d461c7685af875ba451539b092bf0301a19b6408057516c2ce2c59b22bb5d735b24c20f1f2a0396d900536773c87393da645ed76dc308fd525756de1b98dc1f417eed0fd1b66d409b75c7e948bc1e134f55059da5b5bc79263adef8c6d914f83739a519dd068dcc76154f8cb0ff621dd58346f49268eb962c16b1bae489a319ab94e9196f67269dfc9d83561aa7b9d1beeae71665c13272da23a5f4b0fbc54ccaa69097efd6dcf80796ae3ae5b5368acc31818f91c3986c7358b71bee971b26ff2e2ad76280cd8b94a0fe3cf4018d85d5a6327de3ec4424370e03c5c5b7a81da5e9e2b1218134333f42766c4cad15c715c0ec0c059035d58ddd21181adb12f6f0e01e47731ac647487a848f572132322ebcd88502efd600f81fdbae4b61009a9640acf5fa72d9bb1b50c43bb646744a9d3a56e3cfd6cf09f11925ae12c1adbb9a5b67b32edb201ad76a5f25624d84e9c836b3e38359988013b9782e62eaff83b3d46b58f9456a23238fdcc612bdef0e14a79a0523415585e1a8247349f59b7d3c4fda5d2e44f0c18ffa5ec4d0e68d914c9799a01ed0a186833ed45f4527413aaef2403361d3115cd4a92704af18c4ccb984ec36a8a24c224df337b4fbcee7d43c6622229c6c517d1413f973
#TRUST-RSA-SHA256 a2903df1c593588e528af1c42a20a5260fa6aa4c3b24639bb051270d9f6ef922cfba3a3c310452b7aca4382fe8b31745a4cb471575f529595d6397123d13b149df5bc2738cbf295ade1b1e02314fa17b698332e687dca58a85d3b18e0777a8dab607a5dbc602a16be436e77ae30892b1e65449a53b0c6a4c251441cc69f6886cb8bdb6750bc7452ab5c7e7eb5a9b73212167cb86f4cb381cefe5b99cef8365fb6270f55442e4fb6445d11c1900919e78878098b46fc5449d54378e765d2840fbf1e29c44125be61af6b2f8ef8e5958d36cc0e318da56838c77219ee62f66b6413286b8ff8c731bef849d52456231e96eaa983b25ee1e1a4cfa2c2842b50b79b19de42cf17dd22f4216043d9d514b54f11fda0214bd89dad4660748d935355413d4d358e5e08f30e6dd4bf92083d5e194ee6754458c0dcdb96a8941960f21b1a3716be07bf5dc1e230083e14912b4b14d4a59445f7a3eb58d9a2b5132798c8a22386f94d8a41a1948a05b7757327a093bc273ac94e509ecf7949a073df53e49669c68a9323e9a167c9b1af6a66063bb601624b943eedb57edc323afbd6b1126336f7a5e252dd24b1ec094feb4e3bf62003f8e77e61e28acc42e4b72b0c6848bf22e0406d1c0ebf8794e96b672faafce0fbc82bc49babdfc4fd7dc411d9f1e8f08a92c0472a9b4620f1ce3e6908dcdc5553d69c00228d162ddb7ef5ca42cbe6f06
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(39435);
  script_version("1.22");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/24");

  script_cve_id(
    "CVE-2008-2086",
    "CVE-2008-5339",
    "CVE-2008-5340",
    "CVE-2008-5341",
    "CVE-2008-5342",
    "CVE-2008-5343",
    "CVE-2008-5344",
    "CVE-2008-5345",
    "CVE-2008-5346",
    "CVE-2008-5347",
    "CVE-2008-5348",
    "CVE-2008-5349",
    "CVE-2008-5350",
    "CVE-2008-5351",
    "CVE-2008-5352",
    "CVE-2008-5353",
    "CVE-2008-5354",
    "CVE-2008-5356",
    "CVE-2008-5357",
    "CVE-2008-5359",
    "CVE-2008-5360",
    "CVE-2009-1093",
    "CVE-2009-1094",
    "CVE-2009-1095",
    "CVE-2009-1096",
    "CVE-2009-1097",
    "CVE-2009-1098",
    "CVE-2009-1099",
    "CVE-2009-1100",
    "CVE-2009-1101",
    "CVE-2009-1103",
    "CVE-2009-1104",
    "CVE-2009-1106",
    "CVE-2009-1107",
    "CVE-2009-1719"
  );
  script_bugtraq_id(32620, 32892, 32608, 34240, 35381);
  script_xref(name:"Secunia", value:"35118");

  script_name(english:"Mac OS X : Java for Mac OS X 10.5 Update 4");
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
"The remote Mac OS X 10.5 host is running a version of Java for
Mac OS X that is missing Update 4.

The remote version of this software contains several security
vulnerabilities.  A remote attacker could exploit these issues to
bypass security restrictions, disclose sensitive information, cause a
denial of service, or escalate privileges."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.apple.com/kb/HT3632"
  );
  # http://lists.apple.com/archives/Security-announce/2009/Jun/msg00003.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8284f0fe"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to Java for Mac OS X 10.5 Update 4 (JavaVM Framework 12.3.0)
or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2009-1096");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_set_attribute(attribute:"metasploit_name", value:'Sun Java Calendar Deserialization Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(94);

  script_set_attribute(attribute:"patch_publication_date", value:"2009/06/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/06/17");

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
  local_var buf, ret;

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
  return buf;
}


packages = get_kb_item("Host/MacOSX/packages");
if (!packages) exit(1, "The 'Host/MacOSX/packages' KB item is missing.");

uname = get_kb_item("Host/uname");
if (!uname) exit(1, "The 'Host/uname' KB item is missing.");


# Mac OS X 10.5 only.
if (egrep(pattern:"Darwin.* 9\.", string:uname))
{
  plist = "/System/Library/Frameworks/JavaVM.framework/Versions/A/Resources/version.plist";
  cmd = string(
    "cat ", plist, " | ",
    "grep -A 1 CFBundleVersion | ",
    "tail -n 1 | ",
    'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\''
  );
  version = exec(cmd:cmd);
  if (!strlen(version)) exit(1, "Failed to get version info from '"+plist+"'.");

  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  # Fixed in version 12.3.0
  if (
    ver[0] < 12 ||
    (ver[0] == 12 && ver[1] < 3)
  )
  {
    gs_opt = get_kb_item("global_settings/report_verbosity");
    if (gs_opt && gs_opt != 'Quiet')
    {
      report =
        '\n  Installed version : ' + version +
        '\n  Fixed version     : 12.3.0\n';
      security_hole(port:0, extra:report);
    }
    else security_hole(0);
  }
  else exit(0, "The remote host is not affected since JavaVM Framework " + version + " is installed.");
}

