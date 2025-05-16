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
  script_id(181375);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/16");

  script_cve_id(
    "CVE-2023-36788",
    "CVE-2023-36792",
    "CVE-2023-36793",
    "CVE-2023-36794",
    "CVE-2023-36796"
  );
  script_xref(name:"MSKB", value:"5029915");
  script_xref(name:"MSKB", value:"5029916");
  script_xref(name:"MSKB", value:"5029917");
  script_xref(name:"MSKB", value:"5029919");
  script_xref(name:"MSKB", value:"5029920");
  script_xref(name:"MSKB", value:"5029921");
  script_xref(name:"MSKB", value:"5029922");
  script_xref(name:"MSKB", value:"5029923");
  script_xref(name:"MSKB", value:"5029924");
  script_xref(name:"MSKB", value:"5029925");
  script_xref(name:"MSKB", value:"5029926");
  script_xref(name:"MSKB", value:"5029927");
  script_xref(name:"MSKB", value:"5029928");
  script_xref(name:"MSKB", value:"5029929");
  script_xref(name:"MSKB", value:"5029931");
  script_xref(name:"MSKB", value:"5029932");
  script_xref(name:"MSKB", value:"5029933");
  script_xref(name:"MSKB", value:"5029937");
  script_xref(name:"MSKB", value:"5029938");
  script_xref(name:"MSKB", value:"5029940");
  script_xref(name:"MSKB", value:"5029941");
  script_xref(name:"MSKB", value:"5029942");
  script_xref(name:"MSKB", value:"5029943");
  script_xref(name:"MSKB", value:"5029944");
  script_xref(name:"MSKB", value:"5029945");
  script_xref(name:"MSKB", value:"5029946");
  script_xref(name:"MSKB", value:"5029947");
  script_xref(name:"MSKB", value:"5029948");
  script_xref(name:"MSKB", value:"5030030");
  script_xref(name:"MSKB", value:"5030160");
  script_xref(name:"MSFT", value:"MS23-5029916");
  script_xref(name:"MSFT", value:"MS23-5029917");
  script_xref(name:"MSFT", value:"MS23-5029919");
  script_xref(name:"MSFT", value:"MS23-5029920");
  script_xref(name:"MSFT", value:"MS23-5029921");
  script_xref(name:"MSFT", value:"MS23-5029922");
  script_xref(name:"MSFT", value:"MS23-5029923");
  script_xref(name:"MSFT", value:"MS23-5029924");
  script_xref(name:"MSFT", value:"MS23-5029925");
  script_xref(name:"MSFT", value:"MS23-5029926");
  script_xref(name:"MSFT", value:"MS23-5029927");
  script_xref(name:"MSFT", value:"MS23-5029928");
  script_xref(name:"MSFT", value:"MS23-5029929");
  script_xref(name:"MSFT", value:"MS23-5029931");
  script_xref(name:"MSFT", value:"MS23-5029932");
  script_xref(name:"MSFT", value:"MS23-5029933");
  script_xref(name:"MSFT", value:"MS23-5029937");
  script_xref(name:"MSFT", value:"MS23-5029938");
  script_xref(name:"MSFT", value:"MS23-5029940");
  script_xref(name:"MSFT", value:"MS23-5029941");
  script_xref(name:"MSFT", value:"MS23-5029942");
  script_xref(name:"MSFT", value:"MS23-5029943");
  script_xref(name:"MSFT", value:"MS23-5029944");
  script_xref(name:"MSFT", value:"MS23-5029945");
  script_xref(name:"MSFT", value:"MS23-5029946");
  script_xref(name:"MSFT", value:"MS23-5029947");
  script_xref(name:"MSFT", value:"MS23-5029948");
  script_xref(name:"MSFT", value:"MS23-5030030");
  script_xref(name:"MSFT", value:"MS23-5030160");
  script_xref(name:"IAVA", value:"2023-A-0470-S");

  script_name(english:"Security Updates for Microsoft .NET Framework (September 2023)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft .NET Framework installation on the remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft .NET Framework installation on the remote host is missing a security update. It is, therefore, affected
by multiple vulnerabilities, as follows:

  - Multiple vulnerabilities in DiaSymReader.dll where parsing an corrupted PDB can result in remote code
    execution. (CVE-2023-36792, CVE-2023-36793, CVE-2023-36794 CVE-2023-36796)

  - A vulnerability in the WPF XML parser where an unsandboxed parser can lead to remote code execution.
    (CVE-2023-36788)");
  # https://devblogs.microsoft.com/dotnet/dotnet-framework-september-2023-security-and-quality-rollup-updates/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3bbdfd35");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36788");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36792");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36793");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36794");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36796");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5029915");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5029916");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5029917");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5029919");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5029920");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5029921");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5029922");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5029923");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5029924");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5029925");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5029926");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5029927");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5029928");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5029929");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5029931");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5029932");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5029933");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5029937");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5029938");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5029940");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5029941");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5029942");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5029943");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5029944");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5029945");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5029946");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5029947");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5029948");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5030030");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5030160");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released security updates for Microsoft .NET Framework.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-36796");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/09/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/09/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_framework");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

var bulletin = 'MS23-09';
var kbs = make_list(
  '5029915',
  '5029916',
  '5029917',
  '5029919',
  '5029920',
  '5029921',
  '5029922',
  '5029923',
  '5029924',
  '5029925',
  '5029926',
  '5029927',
  '5029928',
  '5029929',
  '5029931',
  '5029932',
  '5029933',
  '5029937',
  '5029938',
  '5029940',
  '5029941',
  '5029942',
  '5029943',
  '5029944',
  '5029945',
  '5029946',
  '5029947',
  '5029948',
  '5030030',
  '5030160'
);

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

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
        smb_check_dotnet_rollup(rollup_date:'09_2023', dotnet_ver:version))
      vuln++;
  }
}
if(vuln)
{
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
