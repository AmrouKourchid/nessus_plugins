#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152432);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/12/29");

  script_cve_id("CVE-2021-34480");
  script_xref(name:"MSKB", value:"5005036");
  script_xref(name:"MSKB", value:"5005076");
  script_xref(name:"MSKB", value:"5005088");
  script_xref(name:"MSKB", value:"5005090");
  script_xref(name:"MSKB", value:"5005099");
  script_xref(name:"MSFT", value:"MS21-5005036");
  script_xref(name:"MSFT", value:"MS21-5005076");
  script_xref(name:"MSFT", value:"MS21-5005088");
  script_xref(name:"MSFT", value:"MS21-5005090");
  script_xref(name:"MSFT", value:"MS21-5005099");

  script_name(english:"Security Updates for Internet Explorer (August 2021)");

  script_set_attribute(attribute:"synopsis", value:
"The Internet Explorer installation on the remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Internet Explorer installation on the remote host is missing a security update. It is, therefore, affected by a
memory corruption error in the scripting engine. An unauthenticated, remote attacker can exploit this to execute
arbitrary commands. (CVE-2021-34480)");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/topic/5005036");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/topic/5005076");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/topic/5005088");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/topic/5005090");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/topic/5005099");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB5005036
  -KB5005076
  -KB5005088
  -KB5005090
  -KB5005099");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-34480");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/08/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/08/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:ie");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_check_rollup.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}
include('smb_hotfixes_fcheck.inc');
include('smb_hotfixes.inc');
include('smb_func.inc');

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

var bulletin = 'MS21-08';
var kbs = make_list(
  '5005036',
  '5005076',
  '5005088',
  '5005090',
  '5005099'
);

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit('SMB/Registry/Enumerated');
var os = get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0',  win81:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

var productname = get_kb_item_or_exit('SMB/ProductName', exit_code:1);
if ('Windows 8' >< productname && '8.1' >!< productname)
 audit(AUDIT_OS_SP_NOT_VULN);
if ('Vista' >< productname) audit(AUDIT_OS_SP_NOT_VULN);

if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);

var share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows 8.1 / Windows Server 2012 R2
  # Internet Explorer 11
  hotfix_is_vulnerable(os:'6.3', sp:0, file:'mshtml.dll', version:'11.0.9600.20091', min_version:'11.0.9600.16000', dir:'\\system32', bulletin:bulletin, kb:'5005036') ||

  # Windows Server 2012
  # Internet Explorer 11
  hotfix_is_vulnerable(os:'6.2', sp:0, file:'mshtml.dll', version:'11.0.9600.20091', min_version:'11.0.9600.16000', dir:'\\system32', bulletin:bulletin, kb:'5005036') ||

  # Windows 7 / Server 2008 R2
  # Internet Explorer 11
  hotfix_is_vulnerable(os:'6.1', sp:1, file:'mshtml.dll', version:'11.0.9600.20091', min_version:'11.0.9600.16000', dir:'\\system32', bulletin:bulletin, kb:'5005036') ||

  # Windows Server 2008
  # Internet Explorer 9
  hotfix_is_vulnerable(os:'6.0', sp:2, file:'mshtml.dll', version:'9.0.8112.21581', min_version:'9.0.8112.16000', dir:'\\system32', bulletin:bulletin, kb:'5005036')
)
{
  var report =  '\nNote: The fix for this issue is available in either of the following updates:\n';
  report += '  - KB5005036 : Cumulative Security Update for Internet Explorer\n';

  if(os == '6.3')
  {
    report += '  - KB5005076 : Windows 8.1 / Server 2012 R2 Monthly Rollup\n';
    hotfix_add_report(bulletin:bulletin, kb:'5005076', report);
  }
  else if(os == '6.2')
  {
    report += '  - KB5005099 : Windows Server 2012 Monthly Rollup\n';
    hotfix_add_report(bulletin:bulletin, kb:'5005099', report);
  }
  else if(os == '6.1')
  {
    report += '  - KB5005088 : Windows 7 / Server 2008 R2 Monthly Rollup\n';
    hotfix_add_report(bulletin:bulletin, kb:'5005088', report);
  }
  else if(os == '6.0')
  {
    report += '  - KB5005090 : Windows Server 2008 Monthly Rollup\n';
    hotfix_add_report(bulletin:bulletin, kb:'5005090', report);
  }

  set_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);

  var port = kb_smb_transport();

  hotfix_security_warning();
  hotfix_check_fversion_end();
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, hotfix_get_audit_report());
}

