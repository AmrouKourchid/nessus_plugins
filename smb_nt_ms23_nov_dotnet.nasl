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
  script_id(185887);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/04");

  script_cve_id("CVE-2023-36049", "CVE-2023-36560", "CVE-2024-29059");
  script_xref(name:"MSKB", value:"5031984");
  script_xref(name:"MSKB", value:"5031987");
  script_xref(name:"MSKB", value:"5031988");
  script_xref(name:"MSKB", value:"5031989");
  script_xref(name:"MSKB", value:"5031990");
  script_xref(name:"MSKB", value:"5031991");
  script_xref(name:"MSKB", value:"5031993");
  script_xref(name:"MSKB", value:"5031995");
  script_xref(name:"MSKB", value:"5031999");
  script_xref(name:"MSKB", value:"5032000");
  script_xref(name:"MSKB", value:"5032004");
  script_xref(name:"MSKB", value:"5032005");
  script_xref(name:"MSKB", value:"5032006");
  script_xref(name:"MSKB", value:"5032007");
  script_xref(name:"MSKB", value:"5032008");
  script_xref(name:"MSKB", value:"5032009");
  script_xref(name:"MSKB", value:"5032010");
  script_xref(name:"MSKB", value:"5032011");
  script_xref(name:"MSKB", value:"5032012");
  script_xref(name:"MSFT", value:"MS23-5031984");
  script_xref(name:"MSFT", value:"MS23-5031987");
  script_xref(name:"MSFT", value:"MS23-5031988");
  script_xref(name:"MSFT", value:"MS23-5031989");
  script_xref(name:"MSFT", value:"MS23-5031990");
  script_xref(name:"MSFT", value:"MS23-5031991");
  script_xref(name:"MSFT", value:"MS23-5031993");
  script_xref(name:"MSFT", value:"MS23-5031995");
  script_xref(name:"MSFT", value:"MS23-5031999");
  script_xref(name:"MSFT", value:"MS23-5032000");
  script_xref(name:"MSFT", value:"MS23-5032004");
  script_xref(name:"MSFT", value:"MS23-5032005");
  script_xref(name:"MSFT", value:"MS23-5032006");
  script_xref(name:"MSFT", value:"MS23-5032007");
  script_xref(name:"MSFT", value:"MS23-5032008");
  script_xref(name:"MSFT", value:"MS23-5032009");
  script_xref(name:"MSFT", value:"MS23-5032010");
  script_xref(name:"MSFT", value:"MS23-5032011");
  script_xref(name:"MSFT", value:"MS23-5032012");
  script_xref(name:"IAVA", value:"2023-A-0618-S");
  script_xref(name:"IAVA", value:"2024-A-0178-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2025/02/25");

  script_name(english:"Security Updates for Microsoft .NET Framework (November 2023)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft .NET Framework installation on the remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft .NET Framework installation on the remote host is missing a security update. It is, therefore, affected
by multiple vulnerabilities, as follows:

  - Security feature bypass in ASP.NET. An attacker can bypass the security checks that prevents an attacker
    from accessing internal applications in a website. (CVE-2023-36560)

  - Privilege escalation vulnerability in FTP component of .NET Framework. An attacker can inject arbitrary
    commands to the FTP server. (CVE-2023-36049)

  - Information disclosure vulnerability in .NET Framework. An attacker can obtain the ObjRef URI which could
    lead to remote code execution. (CVE-2024-29059");
  # https://devblogs.microsoft.com/dotnet/dotnet-framework-november-2023-security-and-quality-rollup/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8ab9cfd4");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36049");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36560");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-29059");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5031984");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5031987");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5031988");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5031989");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5031990");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5031991");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5031993");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5031995");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5031999");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5032000");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5032004");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5032005");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5032006");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5032007");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5032008");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5032009");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5032010");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5032011");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5032012");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released security updates for Microsoft .NET Framework.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-36049");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/11/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/11/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_framework");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2023-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

var bulletin = 'MS23-11';
var kbs = make_list(
  '5031984',
  '5031987',
  '5031988',
  '5031989',
  '5031990',
  '5031991',
  '5031993',
  '5031995',
  '5031999',
  '5032000',
  '5032004',
  '5032005',
  '5032006',
  '5032007',
  '5032008',
  '5032009',
  '5032010',
  '5032011',
  '5032012'
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
        smb_check_dotnet_rollup(rollup_date:'11_2023', dotnet_ver:version))
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
