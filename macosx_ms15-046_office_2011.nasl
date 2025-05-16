#TRUSTED ab3ee95c17ecc842a6831908606bdb01c9d83039bfecee9fc2a1bdeb6b69c8461cd1424c7cf99f348eddba8e304719db0f05dc5afd18aff8205185b3a2c2a96dcae4bd8d20eb665597660799b0adc7b7fa123b92b4ac7afa8740a7191ce1e96c9ee916eff02676ddb338ee44582f4e31d4fa36030a3012c8c3100411d8cf5ffe5c72d4c69e2d7df21bc38141d65a79e26e49fb16f0ecbfcd3a2327ed8b219da45f4e7810b5764adf71bc2fcfb44e065f7d830037b6960b495f2762af9cb448590b2a10a321dc7aae4dc48079bd34593ed7eb0246eb527da32c9f1533dec3747bbfc9b36a7a8275b61ae934079255cf65fb81ad3d6920a123e3841a72e734883ff2bc0f2dd726927bc41432ad30fbfb192d418d44f7b5a7559959ba9f06aaad23d98e134925491770ef95ec30b66a0e7f3a590f9007d1995477783ce9d216879083229961649bb61b6c705b02d934a8ec312dc4d0f1585e8df4397f26b785dd5b001fbcc574d21094700ef350951b0b5467d49ab6c9835a17a1a660eb4113554d36a1b754c9a7bf25052a28a3d94021df787396574e14b7945c4a15fbd5d42105f2aec790866a2c809bee48bce6899bc263b13c2fb37b6051a00c9f763765193684f1651ed67ea83dfeb9cb54d7db6863e9209aa00a08b8b9883d617584f918c78835e97152e32771efdb22d8fc4691db7f88d918fd10d45b1a9a4e226589d2b4
#TRUST-RSA-SHA256 18c5ad4807cb0870da21f35d0bf81129746ff15382a47f435d835a5b751e23e004456622abbfaa6d51086f833007588c7b5a611e175e7231ddf924adf8b233715065e9f104e6801a73468ff2857883d669eebf25c8166be8025d8093e98ef394bee22a50075ae83dfa7e83c593287d3923dd69e5c8a2704d78a656ab46120b61f65b3ec8db528c6c563eb4c157e8a59d9a5369e8b847f9bfab700ef34461b1fec755c8eedb033f9b4187f90c336d592f9c5b49e4daf4b1592d6cd22685026e25bac4a5105aaaf2886a29dc2c066a72cf87919bf990822d8b1b00dbf705239fa4517598d20a10aa7c79b7b51378e1bf2c4080c8cc93f7b2ffe910f5aefbb5a247b2b0e3251e3431c645dbaecce93034dc604d68539705b022060edbf545f88af001ea0e4408ba46c04d12363b96a1ef4966c60166ed615817b8eceeb6c0918bb68da37a17cec1fad3d14798705a0d09e2672f9af2522c7312c494b09bafb0fe937bbff258540ee7e13dd02c6945b622b0b3f5d7f630690437e6120ca55df6131060691a0abfd2100a47753b2e3768bb209d897dec9039ec4ad6ec884a76dfbd3bb133c5dae5e3b8a351f3b2622ac550c1ae324a227b90fb673eca8ec14ad93323381ccadd8f207a76ce52013a20a16b5a1c776fa73810ac9d4bc42f37fd5ef2a6cdd503430f6bb7eb537f6bc923de5095196d4f627a656b58996ee668cba33637
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(83415);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_cve_id("CVE-2015-1682");
  script_bugtraq_id(74481);
  script_xref(name:"MSFT", value:"MS15-046");
  script_xref(name:"IAVA", value:"2015-A-0103-S");
  script_xref(name:"MSKB", value:"3048688");

  script_name(english:"MS15-046: Vulnerability in Microsoft Office Could Allow Remote Code Execution (3057181)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Mac OS X host is affected by a
remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host has a version of Microsoft Word installed
that is affected by a remote code execution vulnerability due to
improper handling of objects in memory. A remote attacker can exploit
this vulnerability by convincing a user to open a specially crafted
file, resulting in execution of arbitrary code in the context of the
current user.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms15-046");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a patch for Office for Mac 2011.

Note that Microsoft has re-released the patch to update the version
of Microsoft Office for Mac to version 14.5.1 to address a potential
issue with Microsoft Outlook for Mac. Microsoft recommends that this
update is applied.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/05/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2011::mac");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word_for_mac:2011");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel_for_mac:2011");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:powerpoint_for_mac:2011");
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

  fixed_version = '14.5.0';
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
