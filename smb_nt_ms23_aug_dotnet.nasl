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
  script_id(179664);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/09/15");

  script_cve_id("CVE-2023-36873", "CVE-2023-36899");
  script_xref(name:"MSKB", value:"5028946");
  script_xref(name:"MSKB", value:"5028947");
  script_xref(name:"MSKB", value:"5028948");
  script_xref(name:"MSKB", value:"5028950");
  script_xref(name:"MSKB", value:"5028951");
  script_xref(name:"MSKB", value:"5028952");
  script_xref(name:"MSKB", value:"5028953");
  script_xref(name:"MSKB", value:"5028954");
  script_xref(name:"MSKB", value:"5028955");
  script_xref(name:"MSKB", value:"5028956");
  script_xref(name:"MSKB", value:"5028957");
  script_xref(name:"MSKB", value:"5028958");
  script_xref(name:"MSKB", value:"5028960");
  script_xref(name:"MSKB", value:"5028961");
  script_xref(name:"MSKB", value:"5028962");
  script_xref(name:"MSKB", value:"5028963");
  script_xref(name:"MSKB", value:"5028967");
  script_xref(name:"MSKB", value:"5028968");
  script_xref(name:"MSKB", value:"5028969");
  script_xref(name:"MSKB", value:"5028970");
  script_xref(name:"MSKB", value:"5028973");
  script_xref(name:"MSKB", value:"5028974");
  script_xref(name:"MSKB", value:"5028975");
  script_xref(name:"MSKB", value:"5028976");
  script_xref(name:"MSKB", value:"5028977");
  script_xref(name:"MSKB", value:"5028978");
  script_xref(name:"MSKB", value:"5028979");
  script_xref(name:"MSKB", value:"5028980");
  script_xref(name:"MSKB", value:"5028981");
  script_xref(name:"MSKB", value:"5028982");
  script_xref(name:"MSFT", value:"MS23-5028946");
  script_xref(name:"MSFT", value:"MS23-5028947");
  script_xref(name:"MSFT", value:"MS23-5028948");
  script_xref(name:"MSFT", value:"MS23-5028950");
  script_xref(name:"MSFT", value:"MS23-5028951");
  script_xref(name:"MSFT", value:"MS23-5028952");
  script_xref(name:"MSFT", value:"MS23-5028953");
  script_xref(name:"MSFT", value:"MS23-5028954");
  script_xref(name:"MSFT", value:"MS23-5028955");
  script_xref(name:"MSFT", value:"MS23-5028956");
  script_xref(name:"MSFT", value:"MS23-5028957");
  script_xref(name:"MSFT", value:"MS23-5028958");
  script_xref(name:"MSFT", value:"MS23-5028960");
  script_xref(name:"MSFT", value:"MS23-5028961");
  script_xref(name:"MSFT", value:"MS23-5028962");
  script_xref(name:"MSFT", value:"MS23-5028963");
  script_xref(name:"MSFT", value:"MS23-5028967");
  script_xref(name:"MSFT", value:"MS23-5028968");
  script_xref(name:"MSFT", value:"MS23-5028969");
  script_xref(name:"MSFT", value:"MS23-5028970");
  script_xref(name:"MSFT", value:"MS23-5028973");
  script_xref(name:"MSFT", value:"MS23-5028974");
  script_xref(name:"MSFT", value:"MS23-5028975");
  script_xref(name:"MSFT", value:"MS23-5028976");
  script_xref(name:"MSFT", value:"MS23-5028977");
  script_xref(name:"MSFT", value:"MS23-5028978");
  script_xref(name:"MSFT", value:"MS23-5028979");
  script_xref(name:"MSFT", value:"MS23-5028980");
  script_xref(name:"MSFT", value:"MS23-5028981");
  script_xref(name:"MSFT", value:"MS23-5028982");
  script_xref(name:"IAVA", value:"2023-A-0406-S");

  script_name(english:"Security Updates for Microsoft .NET Framework (August 2023)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft .NET Framework installation on the remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft .NET Framework installation on the remote host is missing a security update. It is, therefore, affected
by multiple vulnerabilities, as follows:

  - A remote code execution vulnerability in applications running on IIS using their parent application's
    Application Pool which can lead to privilege escalation and other security bypasses. (CVE-2023-36899)

  - A spoofing vulnerability where an unauthenticated remote attacker can sign ClickOnce deployments without
    a valid code signing certificate. (CVE-2023-36873)");
  # https://devblogs.microsoft.com/dotnet/dotnet-framework-august-2023-security-and-quality-rollup-updates/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?31a7e1cb");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36873");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36899");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5028946");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5028947");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5028948");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5028950");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5028951");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5028952");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5028953");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5028954");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5028955");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5028956");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5028957");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5028958");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5028960");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5028961");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5028962");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5028963");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5028967");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5028968");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5028969");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5028970");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5028973");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5028974");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5028975");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5028976");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5028977");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5028978");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5028979");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5028980");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5028981");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5028982");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released security updates for Microsoft .NET Framework.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-36899");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/08/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/08/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/08/10");

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

var bulletin = 'MS23-06';
var kbs = make_list(
  '5028946',
  '5028947',
  '5028948',
  '5028950',
  '5028951',
  '5028952',
  '5028953',
  '5028954',
  '5028955',
  '5028956',
  '5028957',
  '5028958',
  '5028960',
  '5028961',
  '5028962',
  '5028963',
  '5028967',
  '5028968',
  '5028969',
  '5028970',
  '5028973',
  '5028974',
  '5028975',
  '5028976',
  '5028977',
  '5028978',
  '5028979',
  '5028980',
  '5028981',
  '5028982'
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
        smb_check_dotnet_rollup(rollup_date:'08_2023', dotnet_ver:version))
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
