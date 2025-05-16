#TRUSTED 41b7a19db5e51fe8fe0ca09937bffed08b230b77f80afa30d9ca1a5c160870d2e6e070c0ec198d28ded28808ecfaf23af4c7302337eacca8870439f5122c72b49f62957bec693f938e6fad4e14f4395ef7bf619aab6fff18fdda57bdf321df91a21721087b75bcb82c3eba459595e93134768c99870f0f0c50b6e148fcea556dedd71a623281c02af74263225cbb769b88f7730eb5e898b93c2600640ea39ad0c681bfc819f02091a2f56286a983ae2a1db6cd2629b928c24b1e79fb1f74b9aa1cc90c02e423e40137898d5bbe3d91aeaf5a995db730210af851aa1e4d4e5afe5cc723e541a5219c428837e961e85e78158e6d741525956ebdbc39dab75555975c812174a80701679087f4e51a095f6a8b1accf1a74dd4ddf83f7e88ce94c40e567ce2879292c35a0c85928dc2a2b003533d132da86093a49d8da4c092b0b00cafa588b8f9ec01de096efe77770e2619b18d4e16d6283fd4014d3194bceebac4511944209722aeead0a75c880e0a40184e01aeff9ffb67c2f58fb2351f4572000844b2b48ea235906a4bd1007da96f2b2170aeed3958bccf51a14a52029d6bca3bdd568b0729a0f05f91b9199d65f3707792ad0bc9062cb5d8e87013d4637365540852070e435e276353daad80e665e5741ab1a29a12dbee022b6df063d6f6532ad81b5e1ce22fa38c03baadd216bf2977e5f05302490fc8b724c73d5b1df6bf
#TRUST-RSA-SHA256 9195bb55dbbc54ddc47ef42f7317ca8d0bba27d9f9a98e027175007a9ad8a4f1a8db781c5f78ad5f1f372e10cf8cf0ec1b49080856a558ca6ebde11c7b64e50c82e1a9ad10613df843a08e8eba0784a8c65027bda0a4538936e6bed14488075e482be0cdf5b527d34acec6d8e7ca4f4089a75bedc670757b828d4894d460823209285b9d8b1b42017c5569de9890ba0f0b680f089cb182200abb7a588d78488a0749351c9387b0865a4988406a80995317d19485bd2f2918fe7081d34061517dbde906fccd8720ba6ef1138b4f673756f26d91f78337ab26da074e3daa9e6688e7d7d9ca64c2a20ee1b5ae5c0579d215dff67727119ab6d2989747c7f6a05a7e78e420ce7e04459bbb8a2b217cea314933ce06674d37580e9c25998ea8b4a5bbedb03f7586808103aa22187a4d8ab4b0361c4439aafb76df23e1b5bec84f975a5c40179443e41bb0bde0ab85c660cd6096357eb7902a66bc94db245140278cba38363a85930474cf485cba7b31a2ea1f510eac0a4a68f2e01d7c270de0e70e4d3aebf94f05cfe912c99c34fb2fc4ff0d5a0d77fa40b3b596183f9ec989b30e802bf3adfe996b6a775c6db19f0b7b1fee293cf0cf7e8399f9aa81c6a5c2dd96568085f32eb2ec4a784716d50eb77dfc26abf882ca8f11b37ebee7473d6576323f00af80a6748f2c471af1c0fe5d36e2177d0c83cd5bbedba24c3552fb3c93684f
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(53374);
  script_version("1.33");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/24");

  script_cve_id(
    "CVE-2011-0097",
    "CVE-2011-0098",
    "CVE-2011-0101",
    "CVE-2011-0103",
    "CVE-2011-0104",
    "CVE-2011-0105",
    "CVE-2011-0655",
    "CVE-2011-0656",
    "CVE-2011-0976",
    "CVE-2011-0977",
    "CVE-2011-0978",
    "CVE-2011-0979",
    "CVE-2011-0980"
  );
  script_bugtraq_id(
    46225,
    46226,
    46227,
    46228,
    46229,
    47201,
    47243,
    47244,
    47245,
    47251,
    47252
  );
  script_xref(name:"MSFT", value:"MS11-021");
  script_xref(name:"IAVA", value:"2011-A-0045-S");
  script_xref(name:"MSFT", value:"MS11-022");
  script_xref(name:"MSFT", value:"MS11-023");
  script_xref(name:"MSKB", value:"2489279");
  script_xref(name:"MSKB", value:"2489283");
  script_xref(name:"MSKB", value:"2489293");
  script_xref(name:"MSKB", value:"2505924");
  script_xref(name:"MSKB", value:"2505927");
  script_xref(name:"MSKB", value:"2505935");
  script_xref(name:"MSKB", value:"2525412");

  script_name(english:"MS11-021 / MS11-022 / MS11-023: Vulnerabilities in Microsoft Office Could Allow Remote Code Execution (2489279 / 2489283 / 2489293) (Mac OS X)");
  script_summary(english:"Check version of Microsoft Office");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Mac OS X host is affected by
multiple remote code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host is running a version of Microsoft Office that
is affected by several vulnerabilities.

If an attacker can trick a user on the affected host into opening a
specially crafted Office file, these issues could be leveraged to
execute arbitrary code subject to the user's privileges.");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms11-021");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms11-022");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms11-023");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Office for Mac 2011,
Office 2008 for Mac, Office 2004 for Mac, and Open XML File Format
Converter for Mac.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2011-0980");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'White_Phosphorus');
  script_set_attribute(attribute:"metasploit_name", value:'MS11-021 Microsoft Office 2007 Excel .xlb Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/02/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2004::mac");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2008::mac");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2011::mac");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:open_xml_file_format_converter:::mac");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2011-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

prod = 'Office for Mac 2011';
plist = "/Applications/Microsoft Office 2011/Office/MicrosoftComponentPlugin.framework/Versions/14/Resources/Info.plist";
cmd =  'cat \'' + plist + '\' | ' +
  'grep -A 1 CFBundleShortVersionString | ' +
  'tail -n 1 | ' +
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
version = exec(cmd:cmd);
if (version && version =~ "^[0-9]+\.")
{
  version = chomp(version);
  if (version !~ "^14\.") exit(1, "Failed to get the version for "+prod+" - '"+version+"'.");

  installs[prod] = version;

  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  fixed_version = '14.1.0';
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
version = exec(cmd:cmd);
if (version && version =~ "^[0-9]+\.")
{
  version = chomp(version);
  if (version !~ "^12\.") exit(1, "Failed to get the version for "+prod+" - '"+version+"'.");

  installs[prod] = version;

  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  fixed_version = '12.2.9';
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

  fixed_version = '11.6.3';
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

  fixed_version = '1.1.9';
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
