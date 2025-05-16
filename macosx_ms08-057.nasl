#TRUSTED 33cf0f83aa5938894a5ab6e63f062c7ad81a22ed6bf3c302c8f690a396cfc03018cdb2a8802d7e023bb3287a1c418318fdfe91634b56d305cd60415317615f1cd80125763ff3adb3469621e45da38ff8cb7137355fae0a75b4e656d7c91dc3d1e29ff5398f4f2928f5b94330c79dc8446a09ec8d0a4e914f0360b60b376cc3ee46adf2d7e27c37b2be4f169d1b7bf6fd238b348973a2ba568e226cf8605e2b0b81b257bb6f7bc06305436a0b7078548e3504a896bd0a024edd21c2c299b3e4dd3172d1875e6d6989e4b9075e08afe9e6da56e806b0a5704d78dd807f34d25befbdabc26ef463e737883efc58e300e4b90e74ba8cbb59e1f9dba5a1079137764d36670f5d9404e2a2cd4d12687101b095bcc3498cf12bc534aa8fd50ab0d73387f9d55f4a94b97e57220aacc48543010da359e2bb25f48a788f125bffa6abc1464057aef85b87ab9fe992805f8e52cfc7589fce56312da606b5dc86c5ad89cb9f178519af13687d2551f446d59a224a01ad336474fe2c0fa834d284e1c86788c2e49a4870df727f515c3404d54829a7624c24c3a76b68fade691b94c54c504f333e29131ca93106c56b3523beddf741524411344d4b3ff35beed1757f56b1009ba9b0fa267c0c42969c1829e0193c66bc03fef080e66c6cb48331eea8d08a47559bb6c5d2affb45b698a2014c381e4679c24f510455541dcf6f1a575341e9b2ba
#TRUST-RSA-SHA256 7ddafa1992a4ff9fc7d894ba7fc1f12f17dffa0e9a62f5842d64a29a8df271f5a32443f94e8127e27567e57e0fed01761eb77df80d12464fb94c390bcc9d895d277b014ec62f3231bcfcbfe98ca7099bb29237f52bf3fba35276d534e4836c93a33938641e370b154129207c131645bba519f3957a7c9fe7ac269faafde41234542a4fcb735248a19e47e0938b71ff5b86ce3c7419d7b95b6808891429a3ee996474605c5e4441c4d0d6a7838b5f55943aaaa2fe480b38c0ad33d0261188379532da7fb853716608d6633dd6357d0e6481870910cd9acfefca8a6e46b514a637c6e7260f384e807849787ce189ffef85a39f7c7ff41cdb700ea5570454fdfd54fd7989522c4e8d8672d0340288f29159b65b666c4babd707b7f20205813d17c10043ad669b6388fbb359b5c05f47f96793deb135fd4cb9764dfc37d7c30342ad9581191ad7cec13ae0c069f4e692f9b807bc2889aa0275a9a9861f615f0872e2dd9623066ad5f13d724da2a460a5a50b327763bebf2e246f29b6ab28dfb19a9489887c0649405a3629f17201204e278034c3b90e6569667d83dbcef9e8c418b504e9f9f6241decdb6c4d69ee4d231ac9f3708aa580b5499ba1d9bd5b1b426dcf5ee5ccc25b7bc385ba1239fcfedefd9e2e9bf1a0e4d71e577e49791b2420c8fe3ebe4826301949f7afc89a768131d829bf163e900045d42819988df9afb240ec
#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(50059);
  script_version("1.22");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/24");

  script_cve_id("CVE-2008-3471", "CVE-2008-4019");
  script_bugtraq_id(31705, 31706);
  script_xref(name:"MSFT", value:"MS08-057");
  script_xref(name:"MSKB", value:"956416");
  script_xref(name:"MSKB", value:"958267");
  script_xref(name:"MSKB", value:"958304");
  script_xref(name:"MSKB", value:"958312");

  script_name(english:"MS08-057: Vulnerabilities in Microsoft Excel Could Allow Remote Code Execution (956416) (Mac OS X)");
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
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms08-057");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Office 2004 for Mac,
Office 2008 for Mac, and Open XML File Format Converter for Mac.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2008-4019");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189);

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/10/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2004::mac");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2008::mac");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:open_xml_file_format_converter:::mac");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2010-2024 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/MacOSX/packages", "Host/uname");

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
  return buf;
}


packages = get_kb_item("Host/MacOSX/packages");
if (!packages) exit(1, "The 'Host/MacOSX/packages' KB item is missing.");

uname = get_kb_item("Host/uname");
if (!uname) exit(1, "The 'Host/uname' KB item is missing.");
if (!egrep(pattern:"Darwin.*", string:uname)) exit(1, "The host does not appear to be using the Darwin sub-system.");


# Gather version info.
info = '';
installs = make_array();

prod = 'Office 2008 for Mac';
plist = "/Applications/Microsoft Office 2008/Office/MicrosoftComponentPlugin.framework/Versions/12/Resources/Info.plist";
cmd =  'cat \'' + plist + '\' | ' +
  'grep -A 1 CFBundleShortVersionString | ' +
  'tail -n 1 | ' +
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
version = exec(cmd:cmd);
if (version && version =~ "^[0-9]+\.")
{
  version = chomp(version);
  if (version !~ "^12\.") exit(1, "Failed to get the version for "+prod+" - '"+version+"'.");

  installs[prod] = version;

  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  fixed_version = '12.1.3';
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

prod = 'Office 2004 for Mac';
cmd = GetCarbonVersionCmd(file:"Microsoft Component Plugin", path:"/Applications/Microsoft Office 2004/Office");
version = exec(cmd:cmd);
if (version && version =~ "^[0-9]+\.")
{
  version = chomp(version);
  if (version !~ "^11\.") exit(1, "Failed to get the version for "+prod+" - '"+version+"'.");

  installs[prod] = version;

  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  fixed_version = '11.5.2';
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

prod = 'Open XML File Format Converter for Mac';
plist = "/Applications/Open XML Converter.app/Contents/Info.plist";
cmd =  'cat \'' + plist + '\' | ' +
  'grep -A 1 CFBundleShortVersionString | ' +
  'tail -n 1 | ' +
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
version = exec(cmd:cmd);
if (version && version =~ "^[0-9]+\.")
{
  version = chomp(version);
  installs[prod] = version;

  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  fixed_version = '1.0.1';
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
  gs_opt = get_kb_item("global_settings/report_verbosity");
  if (gs_opt && gs_opt != 'Quiet') security_hole(port:0, extra:info);
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
