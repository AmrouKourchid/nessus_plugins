#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(208757);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/31");

  script_cve_id("CVE-2024-43483", "CVE-2024-43484");
  script_xref(name:"MSKB", value:"5044009");
  script_xref(name:"MSKB", value:"5044010");
  script_xref(name:"MSKB", value:"5044011");
  script_xref(name:"MSKB", value:"5044012");
  script_xref(name:"MSKB", value:"5044016");
  script_xref(name:"MSKB", value:"5044017");
  script_xref(name:"MSKB", value:"5044018");
  script_xref(name:"MSKB", value:"5044019");
  script_xref(name:"MSKB", value:"5044021");
  script_xref(name:"MSKB", value:"5044022");
  script_xref(name:"MSKB", value:"5044023");
  script_xref(name:"MSKB", value:"5044024");
  script_xref(name:"MSKB", value:"5044025");
  script_xref(name:"MSKB", value:"5044026");
  script_xref(name:"MSKB", value:"5044028");
  script_xref(name:"MSKB", value:"5044029");
  script_xref(name:"MSKB", value:"5044030");
  script_xref(name:"MSKB", value:"5044033");
  script_xref(name:"MSKB", value:"5044035");
  script_xref(name:"MSFT", value:"MS24-5044009");
  script_xref(name:"MSFT", value:"MS24-5044010");
  script_xref(name:"MSFT", value:"MS24-5044011");
  script_xref(name:"MSFT", value:"MS24-5044012");
  script_xref(name:"MSFT", value:"MS24-5044016");
  script_xref(name:"MSFT", value:"MS24-5044017");
  script_xref(name:"MSFT", value:"MS24-5044018");
  script_xref(name:"MSFT", value:"MS24-5044019");
  script_xref(name:"MSFT", value:"MS24-5044021");
  script_xref(name:"MSFT", value:"MS24-5044022");
  script_xref(name:"MSFT", value:"MS24-5044023");
  script_xref(name:"MSFT", value:"MS24-5044024");
  script_xref(name:"MSFT", value:"MS24-5044025");
  script_xref(name:"MSFT", value:"MS24-5044026");
  script_xref(name:"MSFT", value:"MS24-5044028");
  script_xref(name:"MSFT", value:"MS24-5044029");
  script_xref(name:"MSFT", value:"MS24-5044030");
  script_xref(name:"MSFT", value:"MS24-5044033");
  script_xref(name:"MSFT", value:"MS24-5044035");
  script_xref(name:"IAVA", value:"2024-A-0632-S");

  script_name(english:"Security Updates for Microsoft .NET Framework (October 2024)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft .NET Framework installation on the remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft .NET Framework installation on the remote host is missing a security update. It is, therefore, affected
by multiple denial of service vulnerabilities, as follows:

  - A denial of service (DoS) vulnerability. An attacker can
    exploit this issue to cause the affected component to
    deny system or application services. (CVE-2024-43483,
    CVE-2024-43484)

Note that Nessus has relied upon on the application's self-reported version
number.");
  # https://learn.microsoft.com/en-us/dotnet/framework/release-notes/2024/10-08-October-security-and-quality-rollup
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3d19e8dd");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-43483");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-43484");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5044009");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5044010");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5044011");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5044012");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5044016");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5044017");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5044018");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5044019");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5044021");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5044022");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5044023");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5044024");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5044025");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5044026");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5044028");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5044029");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5044030");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5044033");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5044035");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released security updates for Microsoft .NET Framework.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-43483");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_framework");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

var bulletin = 'MS24-10';
var kbs = make_list(
  '5044009',
  '5044010',
  '5044011',
  '5044012',
  '5044016',
  '5044017',
  '5044018',
  '5044019',
  '5044021',
  '5044022',
  '5044023',
  '5044024',
  '5044025',
  '5044026',
  '5044028',
  '5044029',
  '5044030',
  '5044033',
  '5044035'
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
        smb_check_dotnet_rollup(rollup_date:'10_2024', dotnet_ver:version))
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
