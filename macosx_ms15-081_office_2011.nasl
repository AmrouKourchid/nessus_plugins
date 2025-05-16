#TRUSTED 964d123a7e028ff62bd08d3fff2bd20eaee9545d15d1767208698101dd4c6c3a801de18aee5c737329c0d9fceb892b9787b1720a1b209a19bdaf2677de168a3d5e745a39ad3e0ba8bcc994342ddea3309529ec17a1e81aad02312e236eed1f660d8ec1ebb4c3f39cdb795c8e9c145bb600b4ca9eded3355e8c1145e0dd5ee8714cc8edf607a1ae44a6a3d092da25f7c79cab0566158d4eaee6fcbaaf20ff4a5a5538135b93a5da2d1b6b913df26f0bfb0c8ecb23e852118e325b8273da49f1dd629405c1dda148b4ebe5ba5b171629154d80685ad3978a302f91d355f181e70e8307359fdd48479746405f0795cb07de75ddaf8268f60762bf17d052b933ad21839c64fb6896b319389d0e5c8498fd9d06e9830ad1ff228964ade0dbc2e9d5c82c702f12533fd1a2943c24e2bd537eebb2bde8c67678414bc245b8da43a68198481b59834da899422b698a2c01291878e0e56fd35b0366291ce381068040f7ea9288724a430fa647bbc838a190829940912dd7743994173c4af2d54509e6983e944735270235c63907ca10872919c26b36ffef1b0aad1103a2448fca5639b673999f3dad806db2f1d219bf3c5154cef7fc0d0f81718e1d6a7fb92bdef1f88f553a051a3a61e171ff102c35f70a70360869231e67b54baa28a25cd5b9efed6f5734ceb44a299f0dae03cc7505395f9bcec77fd7bccb822ad71716ea434b4c9fa4
#TRUST-RSA-SHA256 a2c939d073e24c63b6ac6245b24cc73682c8d7bcd3c129681c5bdfec2b5b5d0a7b84116143fe7a803bd8f38a5ecf36620b1df2e8ab8442ef968c0cf673ee50f69e11e16381aa18e708c4a7c2c6fcbcfe9388ac5754508644ee9f604b135b3b79efa2f47efbc388adecec77694750b82ec327b3e266fb5b4e5d9dee57e394c061df06f94c17eba13906706cde9100ef028b1db47147e9780fc7813fbf238c9d2cf8db9d53edef32a6b64059c8aeef19ff17a69432d21dfdf802da4d0b8ec028139d59462bc4f18fb576a6d80f386a7ea256fa40574e64c83bdc8c7c58bd496bab1fc12132d1526adfc7c529df851b0edbf053d3e1c0d705cc04c148a16eca709e1224851f572b87e02b6d357d0c924c69a32e75e2646c2e1b20cffa0c7e6813619237bc3b6e30af1010080ae5e61a64fd7d28f92b893ac18006034ba04000f9817029d0897f7b762be2bedc064828bf8e00924fa07a8ca1ddb97ee9688d65fb567017778ee6c08dd5728c0b74d4b2bb51bfc720cb1e0f50c0152a93fc7e9256d1ec4ea3ba63220a2bb3d37fc03c11b0a56b49c3d6ab9cfadea0a0d2c6611fc77b09020bcfc6b533980d4473a0beea544a380070411ba1088f45dd4566b4825bf5d58087d9e44843c39bf8534fa79cfa058519779d9e509f8517a498efd4f2c295020e61481074b24621fd73d4f85fdcbc3441c49e3f2d3e938daa378e101987ae
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(85349);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_cve_id(
    "CVE-2015-2468",
    "CVE-2015-2469",
    "CVE-2015-2470",
    "CVE-2015-2477"
  );
  script_bugtraq_id(
    76206,
    76212,
    76214,
    76219
  );
  script_xref(name:"MSFT", value:"MS15-081");
  script_xref(name:"IAVA", value:"2015-A-0194-S");
  script_xref(name:"MSKB", value:"3081349");

  script_name(english:"MS15-081: Vulnerability in Microsoft Office Could Allow Remote Code Execution (3072620) (Mac OS X)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Mac OS X host is affected by
multiple remote code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host has a version of Microsoft Office installed
that is affected by multiple remote code execution vulnerabilities :

  - Multiple remote code execution vulnerabilities exist due
    to improper handling of objects in memory. A remote
    attacker can exploit these vulnerabilities by convincing
    a user to open a specially crafted Office file,
    resulting in the execution of arbitrary code in the
    context of the current user. (CVE-2015-2468,
    CVE-2015-2469, CVE-2015-2477)

  - A remote code execution vulnerability exists when Office
    decreases an integer value beyond its intended minimum
    value. A remote attacker can exploit this vulnerability
    by convincing a user to open a specially crafted Office
    file, resulting in the execution of arbitrary code in
    the context of the current user. (CVE-2015-2470)");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms15-081");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a patch for Office for Mac 2011.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/08/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2011:mac");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2016:mac");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

  fixed_version = '14.5.4';
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
