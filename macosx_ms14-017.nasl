#TRUSTED 872f1656441cfd01db6b0edcb602773ddc437790482c84872a0ea5d48029dcec5b39451e87556d0fcb7f6e6d6735a3a50ff2b32a73ca4276209eeba97d9645b4a6515072648999f4ce384cdba42dd897488ccf12988d73fe5e2d4575961efe2d8edcc89d7a610521bf4be73c906314cd426d48be17dffc852ee72292881491d5dfc78c842b30360561bd79e371fcce846e6c24e82341d99816cd91eb7b8ba9b40ff6e0f4e58afb95b11bb9847e4bb9f68d95f4d7d1c03f18d90e8c1e7b4b83c3a0ac8221283f459ce507db4df0cce38211bab40f8c31579898b8201e97affd9eae8d58ab64e3eb9b72f0cf976177b2394cff76e664bc3ed368d3160c2c697963f9cfc80046f577ad52d8a3f335912c760f6411ea2dc76a7990e3559331060f7242b451f2969fea4c13409d0a8cd485c5d5c1f9a97e7a5da4f9c5ec9319665bd8261bc9ebec041d4b3714012aba68a769f4e6229d446a35c1a63af2c77ab20de7034e3e3b428289b4ef6e9809c6daf984330015e1e3b0db49fb4a192210a278a2613064144b1920e13976f561f177a9b9b26e33522f0734301a4e5d3b7ac5fa8fd789282b3ded19e0b0c4568c3c9315a84a1ef3a805267a7317f91f7f0eef6e0751a040802deb278345c5303982b4fbbe2d939e47b8de43397121453c5a3bbee24569eba45d6f8ca548e8bd916475f31f75c5c94f28c6bb3b9532f6af2d49c17d
#TRUST-RSA-SHA256 48c84d4f315830a9614ab48d834d92da53021aea9ce3a168e41f1125f694c9afebefbd8bafd250887c6cc088828d7a211d7976552c184594a687a6affdf8885d18426eae77978aa3d0c3879cda1283ad1fa3eb3791eaa9fcd198547d8b9e8419b0583b9d63627a8c28dffa83bef8d0f77a9917805f3e1aa53689ec313cdcdd62887c764e9c3c7adcb059ea44214979bff0ea53b2dd34c815b73d0a401e75a5045b5c1535529850249d2c589c970c4f5deeac80c05c6e9d07f534f43e001756fa78679f55f0dfe3547967f5577ba02ace9dd30f9d881f4b873880e4dcc78fe311b8993c697691a03d970a069620454cfd919adc0ffe5eda700658998cf28bd65487f8fddbe7f5d3c9198208f45dadbba1a949b3e3377b0e787b6e23f5ec3a535eaf4fc0012af6ee6378437ebddc8edeb4d02ac5aeea7c2f673fab25106aa61d17544beed07eb281348d5e2899d306cb43504c22ca26ea4eda526fb62a9367546310bf581dac7f9c1db6e2ba489dcf6b701012b3a9692080bd183c585ff502716c76945439493de5549d7c42356e79fbd2211ce7193a7e88dece840780ef5eefdd625f2f19928583cb6ed2eb72e2aa132997446a3477a2545a592e122acebb7e3f04e6e94a2d22c9b5331d204feb19aa8fb373af7bd722aacb612358d72c7db9b1aae17aac89bfce08b094a367942cee81e012dfbb8849d8d0dc37519ab48fdeef
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(73414);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_cve_id("CVE-2014-1761");
  script_bugtraq_id(66385);
  script_xref(name:"MSFT", value:"MS14-017");
  script_xref(name:"IAVA", value:"2014-A-0049-S");
  script_xref(name:"MSKB", value:"2939132");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/08/15");

  script_name(english:"MS14-017: Vulnerabilities in Microsoft Word and Office Web Apps Could Allow Remote Code Execution (2949660) (Mac OS X)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Mac OS X host is affected by a
remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host is running a version of Microsoft Word that
is affected by one or more unspecified memory corruption
vulnerabilities.

By tricking a user into opening a specially crafted file, it may be
possible for a remote attacker to take complete control of the system
or execute arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms14-017");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a patch for Office for Mac 2011.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-1761");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'MS14-017 Microsoft Word RTF Object Confusion');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2011::mac");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2023 Tenable Network Security, Inc.");

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

  fixed_version = '14.4.1';
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
