#TRUSTED 6fb5a75a88a2a69efbab2b3d263cb9b4ce51384a4e3015a3173d57b2c5e17a45e3b9ad9a80356632ec83491b66e58c656848e34bd6456d6c86566e10b71d2a1f2fff2b4f66d0e03ba21f82d2d6819e3e4e9c29a56c372618656c14ecd9cc6167be036e4af7d45b9d67201642b0a90841e56db6560315da877e541d056a3cf666c2f546eb52bf27d522708142b5a6d6338e59960539b7624ab3e9fc3db34207f39e1228a8a6a90e5b8dfd0ffffa8a8d7b3ee5eb663def25e05c0c173f98d4c87a0fe71186f52689dfc701f91e8ed5c2aae0745b41a450e46238e2373976988c822fb4bf15b34ceed5865d59c521d9904a0590f7325bf904d791bcbcbe167f45d1b674d6b480566eb6428d2834f581cd63605a77e6ba856b09abf6b87b503814d4a8ee4e1bfe6ca99023017149d4fa9c05f04021c616cadce100d0437c418f1030dfd66a8e08dd66966a24d12980be468f388e912f23466bda9721294badcc8a9ba26671c26fafc62c8d5d35e7c14143085a2c492adad423ea039e8f9699462a18517dcd737988decb950aee6be1f07418d5ae6c7c95e66028dc06e78edb1d0b699e54a1d9bfff8a82ea13f417d60a31942cbf63490a8812b3f98dce0ebe15e46f0c621fd4319f76dbfb2f1ce8a0853b879f1e7b5f1bec64a8714b5eafe4010dbbbe08012cdc685524c67f84a787f0bd4f0f1969032fdc0d237634990e42445e61
#TRUST-RSA-SHA256 7fb172032bbd752c0178a65452f2168b7d99aba555555283914591b263d5ad9177765c77884c60a1aebf45f6adf299b7e786890365f241a0abd09a3db4639a777e9a387dc2ca9dafd5900a1b5c37e836c32b509053530e7021ead53f6a3c0142ffa0acc8b7304a42caf49b4da947856dacb7ee2f802e9c1d72e295e16fe97629df94576d94e7a5a925a19523f656d3909cb768997d48a4f69c6d18b00749ee66fd3589478437a22edf6ebabe130f66329b1de6f7206fbae0af66f5888ec2c98b56412b03f42413315b7023994551af7b5796dc2f9380fa7b1a46f51a5bebeca4b51616abbaa415360cabba49547532e934788faf04e58aa5bb2ae85003347eb120a888dcd3549fd7feac9671966e00ed35831e41946fff2e3d62ebf5a80b8e5fa4eebd34c6fd97856e410931f8850c86e1f23482484ee90a67a5f02396aa0e777e817f26660623743fc7b9c898f2e9a388cddd5353d1526402303a0915c9c925e5e46e87fb531b308aa19485466bb133ac951dfd8368755a52b8b0c5b763eaf8712c44e0078fb65721acf5a8451eaf045b5b25240a28ba15e7ad7518a08b9d45feede82a5c795c1ed087322fab88f21384ebedf4e1d386879c7f85af9f428eb2b007780d2de9865d0cc6c7f345b811a87a2122ca2a7d943847a5df13b719419ef24081ac603a9255dca2290563ab3e2c691b0087d4226f19cad7a24bc80795da
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62909);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_cve_id(
    "CVE-2012-1885",
    "CVE-2012-1886",
    "CVE-2012-1887",
    "CVE-2012-2543"
  );
  script_bugtraq_id(56425, 56426, 56430, 56431);
  script_xref(name:"MSFT", value:"MS12-076");
  script_xref(name:"MSKB", value:"2764047");
  script_xref(name:"MSKB", value:"2764048");

  script_name(english:"MS12-076: Vulnerabilities in Microsoft Excel Could Allow Remote Code Execution (2720184) (Mac OS X)");
  script_summary(english:"Check version of Microsoft Office");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Mac OS X host is affected by
multiple remote code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host is running a version of Microsoft Excel that
is affected by the following vulnerabilities :

  - A heap-based buffer overflow vulnerability exists due to
    the way the application handles memory when opening
    Excel files. (CVE-2012-1885)

  - A memory corruption vulnerability exists due to the way
    the application handles memory when opening Excel
    files. (CVE-2012-1886)

  - A use-after-free vulnerability exists due to the way
    the application handles memory when opening Excel
    files. (CVE-2012-1887)

  - A stack-based buffer overflow vulnerability exists due
    to the way the application handles data structures while
    parsing Excel files. (CVE-2012-2543)

If an attacker can trick a user on the affected host into opening a
specially crafted Excel file, it may be possible to leverage these
issues to execute arbitrary code subject to the user's privileges.");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms12-076");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Office for Mac 2011 and
Office 2008 for Mac.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/11/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2008::mac");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2011::mac");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012-2023 Tenable Network Security, Inc.");

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
path = '/Applications/Microsoft Office 2011';
plist = path + '/Office/MicrosoftComponentPlugin.framework/Versions/14/Resources/Info.plist';
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

  fixed_version = '14.2.5';
  if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
  {
    info +=
      '\n  Product           : ' + prod +
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version + '\n';
  }
}

prod = 'Office 2008 for Mac';
path = '/Applications/Microsoft Office 2008';
plist = path + '/Office/MicrosoftComponentPlugin.framework/Versions/12/Resources/Info.plist';
cmd =  'cat \'' + plist + '\' | ' +
  'grep -A 1 CFBundleShortVersionString | ' +
  'tail -n 1 | ' +
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
version = exec_cmd(cmd:cmd);
if (version && version =~ "^[0-9]+\.")
{
  version = chomp(version);
  if (version !~ "^12\.") exit(1, "Failed to get the version for "+prod+" - '"+version+"'.");

  installs[prod] = version;

  fixed_version = '12.3.5';
  if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
  {
    info +=
      '\n  Product           : ' + prod +
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version + '\n';
  }
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
  if (max_index(keys(installs)) == 0) exit(0, "Office 2008 for Mac / Office for Mac 2011 is not installed.");
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
