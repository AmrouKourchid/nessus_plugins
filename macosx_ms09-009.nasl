#TRUSTED 3bac24f0a12cab20c1bd6ad26206f382ebcbf249f91aaecdcfc5ca5e9dac9d3ac9fa1e07804ba500ba424f5ebc3c9e681fc7be9210be565c7be70e8a2fe02b9d6d6298abdc1684132efeaa5e55199c201812f286527967f7a3c5d495f2f9d38b9a2b9965d4eaecba5c07e56f8377ca4afd3117d6a948a3f8e275ce6de174906f9d964fc8ffc13b365dcd7f502bb1e4db13533d6f10032362e4aae5c2535dda75cc0329706b2d25529e2e93b2ea89f4bba2fbd8a62cecf9620ac4b93f769a22233abd53027ce292a1aa69bcd2c5ceeb5c4d0d5f89b96cb38a1bad9e0e34e12d66e5fe62937ec06e97cbbc3aaf5f116072d444ec84f3476bd90af9af18dd4df484815d908b5427ae232a045317cc95f84572e36723849a313d59d2e237cdb2a4e46c0e33b87c0d1c0d8e21bd3c65d99dd298f6f571e127888e5269da6bf6fae5b87bc42034ba91a8ce296b7bf485e8fb942c81e3c570c8d3e5555cc4d92c9b5803168d74c5ad3130b25546cdd1a2793b85e45a87ccf631260f7148008b818c5325708788cb6ed5c74896562e4a1b81ddafb869695ad8a5f48b38e8d60099cf2455eb893299a1fe0ba91d7d0954e0f96ff9a48119b8c0997b3e13809e2f4cfd2c771783000e42051b1cea86cd7cc667aa5ab90447b64f587ab8d98da930471767957066133766e70bed1dbbdb566817168f97156063e43fb64ea7e5e37c4e553fa4
#TRUST-RSA-SHA256 8f511473259d789df6ff88dda88a3d6a33b4d2e00696075c1fb67a0e04e52171f202c3eace4c67b3bafae8fd634fafdeb412b400d032bddc26d378bdce0cd4e3b41267003f0bfbd78cc99e29e2aab78676b4e6610353540f4f8e0828b9fe6bae13589da74d38eaca4e2770bc574689f2dbd549dab37c9430e85465433a7990456134114cb9fdaa2eda45728d2e2482d8da81d0c7384146e3561f58420820fb520a0bb8eff033cd72a6190bfc25825bd52e0c80aae03b4a805e40d5955a3255280d38cf32f8bd1cb6b6d692d9bdd31ebad857e8a5a7b258c7bf52e8317d1c13104792abb1c31c0e089b3c8564d561fd8ce69f93b8b95fe13911ecec7b435d3bab75074efa8ff087a0d9113f8a70af621f81079a319a3fefb2edf9d454b43d1c6096028988359e3150dcc8670f94aeb67471faf43bf7188cee10e3c3f4753eecdc4018acd5981493751b0848d6a1fb9f9adbadfc74f7ebc3c0d1a799b35f68c8f3b44c33bbf6f8ada4524fe32f2cc1d2bd48eb6d276f3756749f5704602261aea3f3f4add0f0eb3f089da61526205e1c7b05a60e1a3c731b3a4fc2dfe9b31a0e555b9524bf52077a1b45eb6c3dcd5956980a9573883f473b8573b56c6236e2702b7b51d2bcaf05d268995c95b18e7b10571eb0cf9dbc97e5df32bbce1e700c2fcfe7264d22c4d7ae0a5bd6d82ccc17a4b4a071639d0372adb3c2d24406e8b5124a
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(50061);
  script_version("1.23");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/24");

  script_cve_id("CVE-2009-0100", "CVE-2009-0238");
  script_bugtraq_id(33870, 34413);
  script_xref(name:"MSFT", value:"MS09-009");
  script_xref(name:"MSKB", value:"968557");
  script_xref(name:"MSKB", value:"968694");
  script_xref(name:"MSKB", value:"968695");

  script_name(english:"MS09-009: Vulnerabilities in Microsoft Office Excel Could Cause Remote Code Execution (968557) (Mac OS X)");
  script_summary(english:"Check version of Microsoft Office");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Mac OS X host is affected by
multiple remote code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host is running a version of Microsoft Office
Excel that is affected by several vulnerabilities.

If an attacker can trick a user on the affected host into opening a
specially crafted Excel file, these issues could be leveraged to
execute arbitrary code subject to the user's privileges.");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms09-009");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Office 2004 for Mac and
Office 2008 for Mac.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2009-0238");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(94);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/02/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2004::mac");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2008::mac");
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

  fixed_version = '12.1.7';
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

  fixed_version = '11.5.4';
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
