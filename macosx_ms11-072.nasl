#TRUSTED 116492ef69e75699410dd83b870cfd89282b03d46345306dca88a0ddda629c79aa569c3ad0cb99fcc82566246e7fb1a056972430b94c4c77d796d9218f7bd4bc122f8625e47020435980fc008255b3e3a612a3b0dbfd087c48e46bc9ba4aace9fa257d7a39112ec353c83eea36b82360a466d7bc22d3a76af5c9f4aefdfae0ca627535f1b708d6b178a48d40c9f8553d5bbcff7e409b54fa5b2d23740bdffb3d0983eac5a9d1c85ef95d819590632449e4b3b6ebae660625164c571b407d713f87a9707ed4daa3def7f7e7207419c626e863b181f6881a46643785f5bac4f8cd6f05c5134ef1cd19606c38b73f9e29889a416822a6b85eededd84a49063d6976b564f5c9b7802eee1a75770446ab3fefc282a0587d9a34b914756a9c44d33f082846158646941ebc8afa9462594f985e9aea1efa3cca06767f91377ca416d7253898b510ed5278793d609a04c8963b12846b0749cd5b7204c5f1aee8039db9e3400b4e646cc22cb1c08ac4d908854570b915c889d664bd7930158ea12246ca699225d07b837cf812a0138be7c4ea42f498afb35ee4df3e18126bd06c4b7cf7aee40cb2a76ad592e70d6f00882483a19095da6c103959ccb39859f8ad7d0fdfff0c7a390a5aa9528bc4aafbc323252a0dc827b3af0b9c3c9192e1144dbba14ff97fc69b0e112c8b136af07786031bbabda5648c4da7e38f7f2605e771b05332d3
#TRUST-RSA-SHA256 7cf2dccabc96ffa25a7bafa5d8328e35eef93df87cd9a1701ccae2bbda739ddcf874b8c566e42612039d2579418b542aa0c94693fc7e6dc1a9e1d7ecbef40bdff3fe51ff5d080358c2775d97c6c17abed4ec6515c3d838b4f4113896fd21e92bba3773b47dc00c2f02236d18c0e1bca56df798edac6dd0d0b0718d4f2cf5b052a33c4965ded58fa457fc4b25efe17f4b05a1a80dc9af5f6aa25c4e7459858d7dca389bdd6f1def575de09fcfb54441d87a4576e2c1045435ab9af4a82c164f58c1c275d64006ce8e2130d3504d7397d14b8f2db36c59b6be3a18a6501c80895bfe58d55a7b2a399db06034ed8de32d744382cdaf0dfc6df9315ef08e7bd98a5f559a4f42531665893c0475400d41148c562c115532480839a672239103fbf9d6000dc60994bcfcfed8412b91e2ed00609a903e27201f4186445710da2ad5696de0e7256f792dd25a83f510c68c26b4c9900ba7bcca591c1c5ed27f24690cad76b96897078e7908eee704dc9bc27d1e16bf48ddc6178e60a44c0cac04d90d018ed0e9f37c14469bad8b89e8493e0a66442fcbf02c33093c8a3901f13a95947e5cb22f7bdb1e0789f4c9235a06b44551e9cab3b05d6409f98690e777869a679a0dc50f8ca14ea906166cfdb10a17fb0da78e2ca1f4d37b00d73d14b0adff30be5349f3a9247f025bb2af0151888a316a29b5d3086bcea6e674b6db69e595112ffb
#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(56178);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_cve_id("CVE-2011-1987", "CVE-2011-1988", "CVE-2011-1989");
  script_bugtraq_id(49477, 49478, 49518);
  script_xref(name:"MSFT", value:"MS11-072");
  script_xref(name:"MSKB", value:"2587505");
  script_xref(name:"MSKB", value:"2598781");
  script_xref(name:"MSKB", value:"2598782");
  script_xref(name:"MSKB", value:"2598783");
  script_xref(name:"MSKB", value:"2598785");

  script_name(english:"MS11-072: Vulnerabilities in Microsoft Excel Could Allow Remote Code Execution (2587505) (Mac OS X)");
  script_summary(english:"Check version of Microsoft Office");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Mac OS X host is affected by
multiple remote code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host is running a version of Microsoft Excel that
is affected by several vulnerabilities.

If an attacker can trick a user on the affected host into opening a
specially crafted Excel file, these issues could be leveraged to
execute arbitrary code subject to the user's privileges.");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms11-072");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Office 2004 for Mac,
Office 2008 for Mac, Office for Mac 2011, and Open XML File Format
Converter for Mac.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/09/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/09/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2004::mac");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2008::mac");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2011::mac");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:open_xml_file_format_converter:::mac");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2011-2023 Tenable Network Security, Inc.");

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

  fixed_version = '14.1.3';
  if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
  {
    info +=
      '\n  Product           : ' + prod +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version + '\n';
  }
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

  fixed_version = '12.3.1';
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

  fixed_version = '11.6.5';
  if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
  {
    info +=
      '\n  Product           : ' + prod +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version + '\n';
  }
}

prod = 'Open XML File Format Converter for Mac';
plist = "/Applications/Open XML Converter.app/Contents/Info.plist";
cmd =  'cat \'' + plist + '\' | ' +
  'grep -A 1 CFBundleShortVersionString | ' +
  'tail -n 1 | ' +
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
version = exec_cmd(cmd:cmd);
if (version && version =~ "^[0-9]+\.")
{
  version = chomp(version);

  installs[prod] = version;

  fixed_version = '1.2.1';
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
  if (max_index(keys(installs)) == 0) exit(0, "Office for Mac / Open XML File Format Converter is not installed.");
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
