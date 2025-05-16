#TRUSTED 5e37a8198d5216d480b1bf01bb5b290b34a59764d2a69dbb28e0a182270815a1a86bc908ee92b0d56a06658c7250a11857bff884473a657b1c1f59a0540cc8b670e07ddef531e8a9a64e719578293548b3c3ec6dab5d7ff418b5e1e6772248a66ddd9fa9afd3b907fd163833d8aaa795e3065248f51ff972ba2714dd7c19ab89b152717939921f20f4e01ecb890c9046bd3615a29eeecd74b9fb4e60f45dc3a6041109a4f887dffb33c74bfbe3ad6cfbaa84c7aaddf7e7be0738ab45a455b362a5260dc4f0c57cfc73ea96a79ad7c1f2c735cd801c855449757352542f6aeb053bfd267497c72ce8b2667827d020ac00655efc376c6f4af9a910b9dc41e02eaed6f90688185b70aead61607c4668f7a8501aaab2b25a74c382a5b1668351220260d042427fc60331018199f279dcf5b513d1f140faa8707e3a5204aa4860b3706e8cd1bd78d2e6df342bee304de89a59014868e7a835896eb7d9081bcd47de7bdb0f80df5c3e72af0a2697c6fd3e7202bbf10153f5c18abf4fba8cd8af993db5cc04b1b8b49af7cd31a0a9450a4c18d45746d4de1c87488680a6a82408b3ba3dbf771d11bdbeb5b0f98b98d1fda5486ef26cb8b47233115335dd2aabd475c4ec1a349a7cba1e583a4751582686ce19125baa600ae2ac8c5705844576a01beed7e44ba9c65e9ea9e07a90ce5645948f367f061c53f2632cc0c560e845debeb602
#TRUST-RSA-SHA256 9763dc2c18d8e31c7bb324b513af861b860d2ff9d1479d6c8b2ff2c170efd65af0624696c79c3e503e857ebd58188495d3e12834d01203ab2a7dfa2f8d7f3da454be6ec6da03d5667452ca66f80c7ce501bb14ab00fe4096e74c6e096b10c141c48e50efb3b748323c4d1e5445bcc07e3f3004f0de9620a962f671cd145d06e9db4960d82a3471d37fe0aa0f6e1db1ef505f985d70bd1a4392474aef224e85af81782936508cbba39e326626b63da322fd232bdd8baa3c9b5ca57564faecbdf2476a68f98fa387c91da3e036a58155b78f1d4e8576ed396200aeb54d93fb2a971811a042135af13bb7ad81fd5ccf7fa95ce986c6cc595103850efc378c552c995c116e00a73fd8f61c72d1c46a5b03007ab165a142180be287b845b600be6e8e0aa0c00f2b24700343114fedffa965c1d181f178f54f5df3f78ae794db56de7315ef1078db2a82c52ff3503b6bb04867b3ba53de2d23b4bd78c3b5239939c25877846aa41323461a14b8bcfb617973cebdd69557855c84ee143387dd0440bc75adc1cbb4dace58de3a7e854a72f4f44b037e8062a83f27616f85d28bed3830b4a571a35c1aa098e2734d9ac4cca87986d55de7dea9d883db735399bff4cc9a32b624cb76c47e1b71681763ac0e61040ca498c61b6c61521c101b7c1a47d1f4c7613d9c9eca7146447220425fb2220e4d319d39ffc0823d01f164181fc04d74d0
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(66868);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_cve_id("CVE-2013-1331");
  script_bugtraq_id(60408);
  script_xref(name:"MSFT", value:"MS13-051");
  script_xref(name:"MSKB", value:"2817421");
  script_xref(name:"MSKB", value:"2848689");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/22");

  script_name(english:"MS13-051: Vulnerability in Microsoft Office Could Allow Remote Code Execution (2839571) (Mac OS X)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Mac OS X host is affected by a
remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host has a version of Microsoft Office for Mac that
contains a buffer overflow vulnerability because certain Microsoft
Office components for processing PNG files do not properly handle memory
allocation.

If an attacker can trick a user on the affected host into opening a
specially crafted Office file, this issue could be leveraged to execute
arbitrary code subject to the user's privileges.");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms13-051");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a patch for Office for Mac 2011.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-1331");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/06/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2011::mac");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2023 Tenable Network Security, Inc.");

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
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");


# Gather version info.
info = '';
installs = make_array();

prod = 'Office for Mac 2011';
plist = "/Applications/Microsoft Office 2011/Office/MicrosoftComponentPlugin.framework/Versions/14/Resources/Info.plist";
cmd =  'cat \'' + plist + '\' | ' +
  'grep -A 1 CFBundleShortVersionString | ' +
  'tail -n 1 | ' +
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
version = exec_cmd(cmd:cmd);
if (version && version =~ "^[0-9]+\.")
{
  version = chomp(version);
  if (version !~ "^14\.") exit(1, "Failed to get the version for "+prod+" - '"+version+"'.");

  installs[prod] = version;

  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  fixed_version = '14.3.5';
  fix = split(fixed_version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(fix); i++)
    fix[i] = int(fix[i]);

  for (i=0; i<max_index(fix); i++)
    if ((ver[i] < fix[i]))
    {
      info +=
        '\n  Product           : ' + prod +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : ' + fixed_version + '\n';
      break;
    }
    else if (ver[i] > fix[i])
      break;
}


# Report findings.
if (info)
{
  if (report_verbosity > 0) security_hole(port:0, extra:info);
  else security_hole(0);

  exit(0);
}
else
{
  if (max_index(keys(installs)) == 0) exit(0, "Office for Mac 2011 is not installed.");
  else
  {
    msg = 'The host has ';
    foreach prod (sort(keys(installs)))
      msg += prod + ' ' + installs[prod] + ' and ';
    msg = substr(msg, 0, strlen(msg)-1-strlen(' and '));

    msg += ' installed and thus is not affected.';

    exit(0, msg);
  }
}
