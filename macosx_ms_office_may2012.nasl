#TRUSTED 09a1f642f96410cd1feaf4a82eaf765a6fd6130c262e04b1154a7bcf90bdf2e1dfff637e4b5dd40aaf456d422724ea36ab290ec62e425bff0c2438db3e0650234a30cefc0ef6fa7fb8a4a1af1867250df3336bf34e2f64fc60b9d988f57af16f07b8cd4af3513a12ef3dcda2b6d1f3d03df6696af4034fed79047b54579d0e077e4736c61b479d19b0d727ef94dd8c073d06393adae6f82dc54b3599d41001dae2226a7f9df53a6980a831b862d34cdc9f6808cc830c6840452a82eab0c8fd77e96ddb00db19743b620ad4cf8771934a1051ca1e664a15f9f548265166e254f06a7eb7fdffc403e7562e54eb76a58b158221e387c9622502e9ee92d910803e6c5bc56774086763860a8e1e1e63b77726b32509a4109749e7fd950b1772c9570fcb4b0c1aad5926bc145aa884e52b0f8e235440f5874b56cd867cf7c5d7d7a18183ee49b2cc88408d8c2872e46df66a0f515115e12679575a57f18968576aa83cac17203fbb77540df6a7605f91206f66efd304cab62f6bfe34c4930d4b76c2b9827133a56e77f2c13fded13e01942c3b81a66447fb479cc24e4726758adcc56a3105dd8177ac5e42de358cfff5e02bcc81844c8060559e1c111d657a4660a84c970fff2489b479672e98455975de5f7451e87e104e47988d94e0b0e5726322947a3ba2597f20a1d42c49dd0023eb949485e92ff78f10389607111d941e27204a
#TRUST-RSA-SHA256 525a65c43f1bce67f123546f81f64b16321d3722105e9a574256ec46ace1ea39a4272a635ee931e147e6b6e18cc2c8d26ddd77833eeb8a1cc45efdbbc213a5fff6fec84c8c8ae04755e99e487470e4db42bfe1da0f82db6d9403b6fb1392a1ac1fa7727c867f391d4e7fe61f63dbcc06f404ef50a8de5519970f3cf3dd1e6ce883c8f418609074a6227432369975ba173887810e206997f8161f7fe134f6fef2e639eef0f95c5218d0b075f5d41e35419a64280345dcdbb9c75aca8794f0241c8dffd361e09eae034a433a908e0f5e2b94ee80e540a4e252d9b1032ef199c09816a1ebbb4467ec24a46a31edc8d7872feb148ba320c44ae7b221d708e1c330629c46fdebcefabf73aecf104777b50a43231b317f59c7f6c5210a817284e219dc70d2df974b63f6ab1e1636c33c621516e3fb3b8b0cd365c18022fdd91b7cfbf3a31e265c73bf96c11441123c14105957bc89c6e3d91951454e42f19bebd8151575d47dbe1ceb2b906bc132aec952caef8cab84c240d2657e9f41650b40ae2631b9f7c0c993184fce6294f94e5a412b3f8ee20a6eb3df82882cc0460a569d4f56511685b6501ec1b4ee01fd87be941c78a1fb4c44ef1817c1ac9d0f67f1fb3942609b764ed6dda6c1ca9ae396ded92afc808ce8cc29439fed23710c7af5a071f8303a10df8248cc640342912777eec3db3156fd93c4f1a6f7f32b09a924584465
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59046);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_cve_id(
    "CVE-2012-0141",
    "CVE-2012-0142",
    "CVE-2012-0143",
    "CVE-2012-0183",
    "CVE-2012-0184",
    "CVE-2012-1847"
  );
  script_bugtraq_id(53342, 53344, 53373, 53374, 53375, 53379);
  script_xref(name:"MSFT", value:"MS12-029");
  script_xref(name:"MSFT", value:"MS12-030");
  script_xref(name:"MSKB", value:"2665346");
  script_xref(name:"MSKB", value:"2665351");

  script_name(english:"MS12-029 / MS12-030: Vulnerabilities in Microsoft Office Could Allow Remote Code Execution (2680352 / 2663830) (Mac OS X)");
  script_summary(english:"Check version of Microsoft Office");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Mac OS X host is affected by
multiple remote code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host is running a version of Microsoft Office that
is affected by the following vulnerabilities :

  - A memory corruption vulnerability could be triggered
    when parsing specially crafted RTF-formatted data.
    (CVE-2012-0183)

  - Several memory corruption vulnerabilities could be
    triggered when reading a specially crafted Excel file.
    (CVE-2012-0141 / CVE-2012-0142 / CVE-2012-0143 /
    CVE-2012-0184)

  - A record parsing mismatch exists when opening a
    specially crafted Excel file. (CVE-2012-1847)

If a remote attacker can trick a user into opening a malicious file
using the affected install, these vulnerabilities could be leveraged
to execute arbitrary code subject to the user's privileges.");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-12-157/");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2012/Aug/279");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms12-029");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms12-030");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released patches for Office for Mac 2011 and Office 2008
for Mac.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/09");

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


include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");



enable_ssh_wrappers();

if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");

os = get_kb_item("Host/MacOSX/Version");
if (!os) exit(0, "The host does not appear to be running Mac OS X.");


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

  fixed_version = '14.2.2';
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

  fixed_version = '12.3.3';
  if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
  {
    info +=
      '\n  Product           : ' + prod +
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
