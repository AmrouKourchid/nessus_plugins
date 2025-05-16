#TRUSTED 59cd8e51a013527ac95d9dad3ad60f67eb93f69bca5e9a4e5f9fd1e0ee365b8c2d3cc320c05d9219560de66eefe2c56ee1328ef583c7e42b165f0dcf119dd2d60caaf459fcd9b09cd042fe5f98a0de0d2787fff84bcb14084cc855a79c736a2037119e542c342b5a12b0d6b85b0b0dfd245df0f5dca618361795083e5290a8601ef3b4bfc108633d29904f3159e90bc4319f54bf84894a2a0110a73c5bba5fef92f9a0637d114340163fc7fa814c4c2d27c8dc6692a33bca2f9f1e7021b247e5bc4a38ff7bd0d58ccd46bbfda5d29a572f9a2e12662ca6333c97443ce34c7ed44cba416a01b8f4579f4329e54190bfa9574658269899ca8c71bb83a9bdd83de553a823003b2e94b432478b5df1b5661db4f4b40529ee0b9702b508791805fe315d5b0ee40b3501a564f8cccd8f0c82e7724372f0e2322f111c86d610abdab1846e02b7c67731b0bda60cd517419f1e3c8c4e5a2922d2bbcdab8c46bcf251a38715503f59016910a5ec090fd2a6e53dd37b4a47f81009f7f744a9ce69738f4f75f4c47c2c224aefdee58ba2eda53298cd46c155cb8e0ee0274cd7311f01bf096d6ce6359d287a2dd524975025f7a1e082e8fb37fde1a25d7140b620357a59248d0a56b7bf266fb229340b822e782dcf98b3399038077ef6d65c63742a09bb160d9189800a6feb8a89f71cbaf686f89793223463b1e2328c7b36ac819ad6443c7f
#TRUST-RSA-SHA256 2a057a2fb2b8e194e11101e34f47420c9528994a2b01dd47a01c007df4a6db6561f38eacda0c3089ed00f76dca3e979eed64359c43246949728fb5fe9a37af928882d3b40aded2a4edd9d977dda9d7d2d9c39c44124abf282277c9394e8645fe057483a87c0c950aaa95650436342e7c5f291c1ce63780caeb706fb808e07021b6812b62f802ecdc642ed1987ab561a712338aaad90b9d8cdad94f69f89c5d3fb5737caf76184fd26f3ac59c23e4d317a066301c1aed2ca9204347cf167fe0d45dcdce865c3bf9fec1b947ded0db080b4e59526276b0aadf07dc47e5d7590f859bbc8f0d20d2f43999a1856dd69fb5ed90edc0191e66ecf2cafc3d03357fd74a722a6a650e94359d07a0facd3f1361fa14f52c33505cdb3d37f426a3ebb6bed25131191cb47036a94283adfea2e3fe0251b5f1c656fe9c7c60d59b1273abb4c4ab979c0d641023e483baf7424e45b1f9c7049b52b22dece9978763cecf3cf7d3e88937eb8e7823b7520f73da95642d30f426ef72ad4ccc0b5c427f3853d2f23616ad1d8ccc553bf752c7a28aa3e2e8ebcbd4e669675f779c420317c61a3715088eb293278d4eb877c9b6d58be2adc0ac0ae7a1092311060b0f5c34b1f04230d2c548142f3aeded560c785576eb42b64d30009538b6087e6b285b06e4b6cea338c8e16dc1c933271329b520357ed8c0cb6dd435fe3e811ae7f89bcddc209d69ec
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57286);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_cve_id("CVE-2011-1983", "CVE-2011-3403", "CVE-2011-3413");
  script_bugtraq_id(50954, 50956, 50964);
  script_xref(name:"MSFT", value:"MS11-089");
  script_xref(name:"IAVA", value:"2011-A-0166");
  script_xref(name:"MSFT", value:"MS11-094");
  script_xref(name:"MSFT", value:"MS11-096");
  script_xref(name:"MSKB", value:"2590602");
  script_xref(name:"MSKB", value:"2639142");
  script_xref(name:"MSKB", value:"2640241");
  script_xref(name:"MSKB", value:"2644347");
  script_xref(name:"MSKB", value:"2644354");
  script_xref(name:"MSKB", value:"2644358");

  script_name(english:"MS11-089 / MS11-094 / MS11-096 : Vulnerabilities in Microsoft Office Could Allow Remote Code Execution (2590602 / 2639142 / 2640241) (Mac OS X)");
  script_summary(english:"Check version of Microsoft Office");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Mac OS X host is affected by
multiple remote code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host is running a version of Microsoft Office that
is affected by the following vulnerabilities :

  - A use-after-free vulnerability could be triggered when
    reading a specially crafted Word file. (CVE-2011-1983)

  - A memory corruption vulnerability could be triggered
    when reading a specially crafted Excel file.
    (CVE-2011-3403)

  - A memory corruption vulnerability could be triggered
    when reading an invalid record in a specially crafted
    PowerPoint file. (CVE-2011-3413)

If a remote attacker can trick a user into opening a malicious file
using the affected install, these vulnerabilities could be leveraged
to execute arbitrary code subject to the user's privileges.");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms11-089");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms11-094");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms11-096");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a patch for Office for Mac 2011, Office 2008
for Mac, and Office 2004 for Mac.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/12/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2004::mac");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2008::mac");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2011::mac");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2011-2023 Tenable Network Security, Inc.");

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

  fixed_version = '14.1.4';
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

prod = 'Office 2008 for Mac';
plist = "/Applications/Microsoft Office 2008/Office/MicrosoftComponentPlugin.framework/Versions/12/Resources/Info.plist";
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

  fixed_version = '12.3.2';
  if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
  {
    info +=
      '\n  Product           : ' + prod +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version + '\n';
  }
}

prod = 'Office 2004 for Mac';
cmd = GetCarbonVersionCmd(file:"Microsoft Component Plugin", path:"/Applications/Microsoft Office 2004/Office");
version = exec_cmd(cmd:cmd);
if (version && version =~ "^[0-9]+\.")
{
  version = chomp(version);
  if (version !~ "^11\.") exit(1, "Failed to get the version for "+prod+" - '"+version+"'.");

  installs[prod] = version;

  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  fixed_version = '11.6.6';
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
  if (max_index(keys(installs)) == 0) exit(0, "Office for Mac is not installed.");
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
