#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(214274);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/09");

  script_cve_id("CVE-2025-21176");
  script_xref(name:"MSKB", value:"5049614");
  script_xref(name:"MSFT", value:"MS25-5049614");
  script_xref(name:"MSKB", value:"5049618");
  script_xref(name:"MSFT", value:"MS25-5049618");
  script_xref(name:"MSKB", value:"5049620");
  script_xref(name:"MSFT", value:"MS25-5049620");
  script_xref(name:"MSKB", value:"5049622");
  script_xref(name:"MSFT", value:"MS25-5049622");
  script_xref(name:"MSKB", value:"5049624");
  script_xref(name:"MSFT", value:"MS25-5049624");
  script_xref(name:"MSKB", value:"5049993");
  script_xref(name:"MSFT", value:"MS25-5049993");
  script_xref(name:"MSKB", value:"5050013");
  script_xref(name:"MSFT", value:"MS25-5050013");
  script_xref(name:"MSKB", value:"5050180");
  script_xref(name:"MSFT", value:"MS25-5050180");
  script_xref(name:"MSKB", value:"5050181");
  script_xref(name:"MSFT", value:"MS25-5050181");
  script_xref(name:"MSKB", value:"5050182");
  script_xref(name:"MSFT", value:"MS25-5050182");
  script_xref(name:"MSKB", value:"5050183");
  script_xref(name:"MSFT", value:"MS25-5050183");
  script_xref(name:"MSKB", value:"5050184");
  script_xref(name:"MSFT", value:"MS25-5050184");
  script_xref(name:"MSKB", value:"5050185");
  script_xref(name:"MSFT", value:"MS25-5050185");
  script_xref(name:"MSKB", value:"5050186");
  script_xref(name:"MSFT", value:"MS25-5050186");
  script_xref(name:"MSKB", value:"5050187");
  script_xref(name:"MSFT", value:"MS25-5050187");
  script_xref(name:"MSKB", value:"5050188");
  script_xref(name:"MSFT", value:"MS25-5050188");
  script_xref(name:"MSKB", value:"5050416");
  script_xref(name:"MSFT", value:"MS25-5050416");
  script_xref(name:"IAVA", value:"2025-A-0028-S");

  script_name(english:"Security Updates for Microsoft .NET Framework (January 2025)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft .NET Framework installation on the remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft .NET Framework installation on the remote host is missing a security update. It is, therefore, affected
by multiple denial of service vulnerabilities, as follows:

  - A remote code execution vulnerability. An attacker can
    exploit this issue to cause the affected component to
    execute unauthorized code. (CVE-2025-21176)

Note that Nessus has relied upon on the application's self-reported version
number.");
  # https://learn.microsoft.com/en-us/dotnet/framework/release-notes/2025/01-14-january-cumulative-update
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3ee48e6a");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-21176");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5049614");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5049618");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5049620");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5049622");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5049624");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5049993");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5050013");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5050180");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5050181");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5050182");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5050183");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5050184");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5050185");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5050186");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5050187");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5050188");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5050416");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released security updates for Microsoft .NET Framework.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-21176");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(126);

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/01/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/01/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_framework");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

var bulletin = 'MS25-01';
var kbs = make_list(
  '5049614',
  '5049620',
  '5049622',
  '5049624',
  '5049993',
  '5050013',
  '5050180',
  '5050181',
  '5050182',
  '5050183',
  '5050184',
  '5050185',
  '5050186',
  '5050187',
  '5050188',
  '5050416'
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
        smb_check_dotnet_rollup(rollup_date:'01_2025', dotnet_ver:version))
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
