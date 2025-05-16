#TRUSTED 0fdcbd88bcb0f927074c943e96a2adc4c09158f56b1126f4fd32d0cd623eca1c6c7bca5573ebfb740193089fa4d7e47e08cbde9ac15bdb630bb96e919be06ec29a0ea9f315b7cd7e7081ca51b7aab39cf6530b6299bd15c9654c8597067d2465f4df4e2570ec4a2bf0f48ce75e22db2ea57bfd6e0faf24021b116fa8cede270eecf6ae4a6333bb7582004804fa7ed9f604c9609ef611680f9202082e2aefface7a41708431e3a4c6e56c69c4916e5e7746b44f142fccc2439867ce22ba1bbbb1ddf999fa29368c8d29c00b0b69a40b7d14257487823f3d1f58000e2f5d2e598f555220206f3b541de9442b3703a9aab441d3f62da1f34c271e94c236ee208dfe643fdf833a5d9430f759d9cde608a6b7000885a3528c1c4d9dd048698ce7bb63d6b730f79a3fe4fdde954dac9ae4a71600792f32bad3d4c5aa26e805bb9bb7a681c3309e75e5df8139400487b2b1a9e671a75def2d34af4944ff999f94a78d9c3225072668b7bf1618142b356ff87ff8f5a3b4fa7b9b8597eec8e2538e6369421e7536d1f1d4bb804508ae599336909c62cd69460d17a0b7df0da9afb6e5c0818c9c775e4b207a7b3e5ab784419ebc89c38d9a4cbf95cc0c51b954c042c91cb1eeda59ccbaee6a952cde365902fbc625fd29090c3719113124cb365a9418a3b71b7e9937e0c921337e72ee275c6ad3200ee4d52eada9a2e85d49181fee97c709
#TRUST-RSA-SHA256 809aa9208fa2acac5b1e3f55ed52dbb3bef951fa915d0700a36f352ebe7c0832e82da605ed87f6ccf5afad4b07f2d85e997fc7122dd427cd885ecf49356bd4cb62df5e28a902808b0159cd84df0f71df2165a0febe76df57cd565ad717631f98093d81f6df53d361af0f891dcf92cf23bc35a89217cc59a01f4cd681e16ee39898bf86544e3f6072e543ae37047b7d494708ba37ed3a269cf6f831af23dffd06092e8d78471255b85c5dfdf538cf2f583f5b159010ee65fd6d67be6e8836d2b568034cfae91b14cb1b902103f3d35e82775fdb203e251fa70d21d6e230a742fc678269530b22a42e223add8caf007a12a4b0ec8e174113e1a828dbbf09c6f2a266e9f0391289ddc27747e4ec9756684511c362a240d2748f6b5266a62172567b4dfb9b15b57253c4858a863843ab0bbb4f08a1f8f514fe8de79bdc587d000d34ee3baa38ff60114ee518333f5867bf45dfab164b04c0a79587a4ccf3c30de67a76407b23e8652548301fa0766e1316f2b291b16e3d849dd88bd0a19519168f6aa6c2a5ac944c1dbf46e2e1ca4c35d473cfc9e8572d0c8cdd907b866007206f21105a7de0e98fc5cde03d121cd858ad2a793bdfb588204fb6cbebcce03c2fc27d2692e524b58f3afce19b529a85899ef570d8bd57fddc4c1720b29c4a9613afc86a69de74e4f94b97c1f4f106a6d6a5e19c5f15a0df6332c5f1981aa17163f30b
#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(50065);
  script_version("1.23");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/24");

  script_cve_id(
    "CVE-2010-0258",
    "CVE-2010-0262",
    "CVE-2010-0263",
    "CVE-2010-0264"
  );
  script_bugtraq_id(38550, 38553, 38554, 38555);
  script_xref(name:"MSFT", value:"MS10-017");
  script_xref(name:"MSKB", value:"980150");
  script_xref(name:"MSKB", value:"980837");
  script_xref(name:"MSKB", value:"980839");
  script_xref(name:"MSKB", value:"980840");

  script_name(english:"MS10-017: Vulnerabilities in Microsoft Office Excel Could Allow Remote Code Execution (980150) (Mac OS X)");
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
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms10-017");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Office 2004 for Mac,
Office 2008 for Mac, and Open XML File Format Converter for Mac.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2010-0264");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/03/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/09");
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

  fixed_version = '12.2.4';
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

  fixed_version = '11.5.8';
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

  fixed_version = '1.1.4';
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
