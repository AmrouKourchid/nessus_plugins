#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

# The descriptive text and package checks in this plugin were
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
#

include('compat.inc');

if (description)
{
  script_id(193217);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/12");

  script_cve_id("CVE-2024-21409");
  script_xref(name:"MSKB", value:"5036604");
  script_xref(name:"MSKB", value:"5036605");
  script_xref(name:"MSKB", value:"5036606");
  script_xref(name:"MSKB", value:"5036607");
  script_xref(name:"MSKB", value:"5036608");
  script_xref(name:"MSKB", value:"5036609");
  script_xref(name:"MSKB", value:"5036610");
  script_xref(name:"MSKB", value:"5036611");
  script_xref(name:"MSKB", value:"5036612");
  script_xref(name:"MSKB", value:"5036613");
  script_xref(name:"MSKB", value:"5036614");
  script_xref(name:"MSKB", value:"5036615");
  script_xref(name:"MSKB", value:"5036618");
  script_xref(name:"MSKB", value:"5036619");
  script_xref(name:"MSKB", value:"5036620");
  script_xref(name:"MSKB", value:"5036621");
  script_xref(name:"MSKB", value:"5036624");
  script_xref(name:"MSKB", value:"5036625");
  script_xref(name:"MSKB", value:"5036626");
  script_xref(name:"MSKB", value:"5036627");
  script_xref(name:"MSKB", value:"5036631");
  script_xref(name:"MSKB", value:"5036632");
  script_xref(name:"MSKB", value:"5036633");
  script_xref(name:"MSKB", value:"5036634");
  script_xref(name:"MSKB", value:"5036636");
  script_xref(name:"MSKB", value:"5036637");
  script_xref(name:"MSFT", value:"MS24-5036604");
  script_xref(name:"MSFT", value:"MS24-5036605");
  script_xref(name:"MSFT", value:"MS24-5036606");
  script_xref(name:"MSFT", value:"MS24-5036607");
  script_xref(name:"MSFT", value:"MS24-5036608");
  script_xref(name:"MSFT", value:"MS24-5036609");
  script_xref(name:"MSFT", value:"MS24-5036610");
  script_xref(name:"MSFT", value:"MS24-5036611");
  script_xref(name:"MSFT", value:"MS24-5036612");
  script_xref(name:"MSFT", value:"MS24-5036613");
  script_xref(name:"MSFT", value:"MS24-5036614");
  script_xref(name:"MSFT", value:"MS24-5036615");
  script_xref(name:"MSFT", value:"MS24-5036618");
  script_xref(name:"MSFT", value:"MS24-5036619");
  script_xref(name:"MSFT", value:"MS24-5036620");
  script_xref(name:"MSFT", value:"MS24-5036621");
  script_xref(name:"MSFT", value:"MS24-5036624");
  script_xref(name:"MSFT", value:"MS24-5036625");
  script_xref(name:"MSFT", value:"MS24-5036626");
  script_xref(name:"MSFT", value:"MS24-5036627");
  script_xref(name:"MSFT", value:"MS24-5036631");
  script_xref(name:"MSFT", value:"MS24-5036632");
  script_xref(name:"MSFT", value:"MS24-5036633");
  script_xref(name:"MSFT", value:"MS24-5036634");
  script_xref(name:"MSFT", value:"MS24-5036636");
  script_xref(name:"MSFT", value:"MS24-5036637");
  script_xref(name:"IAVA", value:"2024-A-0219-S");

  script_name(english:"Security Updates for Microsoft .NET Framework (April 2024)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft .NET Framework installation on the remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft .NET Framework installation on the remote host is missing a security update. It is, therefore, affected
by remote code execution vulnerability.");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-21409");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5036604");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5036605");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5036606");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5036607");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5036608");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5036609");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5036610");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5036611");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5036612");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5036613");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5036614");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5036615");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5036618");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5036619");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5036620");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5036621");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5036624");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5036625");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5036626");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5036627");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5036631");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5036632");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5036633");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5036634");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5036636");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5036637");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released security updates for Microsoft .NET Framework.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-21409");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_framework");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_check_dotnet_rollup.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl", "microsoft_net_framework_installed.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('install_func.inc');
include('smb_func.inc');
include('smb_hotfixes.inc');
include('smb_hotfixes_fcheck.inc');

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

var bulletin = 'MS24-04';
var kbs = make_list(
  '5036604',
  '5036605',
  '5036606',
  '5036607',
  '5036608',
  '5036609',
  '5036610',
  '5036611',
  '5036612',
  '5036613',
  '5036614',
  '5036615',
  '5036618',
  '5036619',
  '5036620',
  '5036621',
  '5036624',
  '5036625',
  '5036626',
  '5036627',
  '5036631',
  '5036632',
  '5036633',
  '5036634',
  '5036636',
  '5036637'
);

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit('SMB/Registry/Enumerated');
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp_range(vista:'2' , win7:'1', win8:'0', win81:'0', win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

var share = hotfix_get_systemdrive(exit_on_fail:TRUE, as_share:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

var app = 'Microsoft .NET Framework';
get_install_count(app_name:app, exit_if_zero:TRUE);
var installs = get_combined_installs(app_name:app);

var install, version;
var vuln = 0;

if (installs[0] == 0)
{
  foreach install (installs[1])
  {
    version = install['version'];
    if( version != UNKNOWN_VER &&
        smb_check_dotnet_rollup(rollup_date:'04_2024', dotnet_ver:version))
      vuln++;
  }
}
if(vuln)
{
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
