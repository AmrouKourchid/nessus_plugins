#TRUSTED 32826cb5588acee358ce459244c86f1e03f5a72c919ae1695d27382af767b7d062e6379ee66a3af210d7c4d810b5808d19f29d492dcaf53bc054c16140fb7ff02f00cedfe0d8c43e3ceef73d94daf99f94753a491894aca0f402e1940f3cba4b568701131bc4ea1d3f270282a8c0a5b84d0f65a995c18a03568d6bc87de7b55db1b457c8b910e11172173ca12b30e484c9038ee9eb8add180d959fbab2520222a06fd1cfcb33d9acb5db5004386f577894a634305fec3988925f11ba8dca88384ca7cfd6a6091cb8894549357a008f48851b87bbff4868578e122cfd770a755d12369d4aba983016985be66142e7e808e532a2f12ee67f07fb3e00cf14810ed21c8769aa6f5b7099b4fe0da1145ef6e65b45c22c69da218edd1e08e907fd16086cc79fd2fecb656031051388e19d8a59513e3085ce0152e61d4d1a5c050f715f78573a703675f1b85a08665104f0374d93873802d0a52cb3a5f07818c1a90d851cddbe9d5edf3a12e0eea5bf01a7761f4347223a152aded33155b0562908bdb1dedbd39819a75f3aa3b21914755486f6d83383e0d7695d660d3e2cd4c016929aeb5bb1bd2ecc4200759dce8e9b0772846bd67bc5d4ea0d3b24e4cd6f3e4414702b4577d530d114fb29bf06601a11f41fa61e890c86f45722bc731cf9b780064b27d0f44b97a384ab4187098af597469e7e978270c8de3f86949c1038caeac2c3
#TRUST-RSA-SHA256 3deafb78ec618f83df198c588e458e0ac2c1e312ade4ad176cf2f3312392bb648685ac87f7cd3f10fd875c6b4aa42cc4b491aa342f1ecfeb35a75dc939f8ba2d7a1024ff34456c24a1af425738b66d7482567f03d7165dbc5348bbc4b91f83eb0e7d3c95e937c8cd3372b26cbe4273508c58df4fd2f77b4f31b0f0aeb05b5b7c21b2e8b2d69abc97836147f520970dc517bee39d8b48ca3db191848befe49fe1cb04f1e749eced54a339b8c94065577b468685a1aa67636021c1721217d602b9c803be315655d63cbde83147b60fe2c526a006806e5c67fb4b38da7af6fa6e0d7505a4eca497f3776354910cd3012036253df299d66e38ccc55528484644405b2177b0587e78e15bab1a57b6e192890caa963f3f16dc8e51fd9c82af355cb3bddf90597ae5bcb38b3c655b58e204a25f873fe66e06dc6c0119bda3de018d0d8cb3308ff05a304d3ce41709599c5d83fdd1b34d9f9ce4c9bdb04a2358c5eee2133deac7544c8a1290e17599ed9385f5b49b21da58b56cfb65007a9d8a599d60412bfcf05065ab6130b98514ff5c19f9c0e88cd8a38e14e90b3bfe9531f297a7368da73af30d40a049465b8a7c9ea169bbed0b4656b1574ccd0c0999cdaa8c664f9ff92453a1c718852e75c74d5eb1ce2e51a88740a58476313256f4662c97340ee6bccb550eba356d5be967c0fcef6646eee20096a887cda51720457f043965af
#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(50060);
  script_version("1.23");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/24");

  script_cve_id(
    "CVE-2008-4024",
    "CVE-2008-4025",
    "CVE-2008-4026",
    "CVE-2008-4027",
    "CVE-2008-4028",
    "CVE-2008-4031",
    "CVE-2008-4264",
    "CVE-2008-4266"
  );
  script_bugtraq_id(
    32579,
    32580,
    32581,
    32583,
    32585,
    32594,
    32621,
    32622
  );
  script_xref(name:"MSFT", value:"MS08-072");
  script_xref(name:"MSFT", value:"MS08-074");
  script_xref(name:"MSKB", value:"959070");
  script_xref(name:"MSKB", value:"957173");
  script_xref(name:"MSKB", value:"960401");
  script_xref(name:"MSKB", value:"960402");
  script_xref(name:"MSKB", value:"960403");

  script_name(english:"MS08-072 / MS08-074: Vulnerabilities in Microsoft Office Could Allow Remote Code Execution (957173 / 959070) (Mac OS X)");
  script_summary(english:"Check version of Microsoft Office");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Mac OS X host is affected by
multiple remote code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host is running a version of Microsoft Office that
is affected by several vulnerabilities.

If an attacker can trick a user on the affected host into opening a
specially crafted Excel or Word file, these issues could be leveraged
to execute arbitrary code subject to the user's privileges.");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms08-072");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms08-074");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Office 2004 for Mac,
Office 2008 for Mac, and Open XML File Format Converter for Mac.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2008-4266");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/12/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/12/09");
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

  fixed_version = '12.1.5';
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

  fixed_version = '11.5.3';
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

  fixed_version = '1.0.2';
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
