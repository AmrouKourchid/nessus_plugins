#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(90431);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/07");

  script_cve_id(
    "CVE-2016-0154",
    "CVE-2016-0159",
    "CVE-2016-0160",
    "CVE-2016-0162",
    "CVE-2016-0164",
    "CVE-2016-0166"
  );
  script_bugtraq_id(
    85922,
    85924,
    85936,
    85938,
    85939
  );
  script_xref(name:"MSFT", value:"MS16-037");
  script_xref(name:"MSKB", value:"3148198");
  script_xref(name:"MSKB", value:"3147458");
  script_xref(name:"MSKB", value:"3147461");
  script_xref(name:"MSKB", value:"4014661");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/14");

  script_name(english:"MS16-037: Cumulative Security Update for Internet Explorer (3148531)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a web browser installed that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Internet Explorer installed on the remote host is
missing Cumulative Security Update 3148531. It is, therefore, affected
by multiple vulnerabilities, the majority of which are remote code
execution vulnerabilities. An unauthenticated, remote attacker can
exploit these issues by convincing a user to visit a specially crafted
website, resulting in the execution of arbitrary code in the context
of the current user.");
  script_set_attribute(attribute:"see_also", value:"https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2016/ms16-037");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Internet Explorer 9, 10,
and 11.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-0166");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2016-0160");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:ie");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:ie:9");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:ie:10");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:ie:11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2016-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("smb_reg_query.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS16-037';
kbs = make_list('3148198', '3147458', '3147461', '4014661');

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0',  win81:'0', win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ("Windows 8" >< productname && "8.1" >!< productname)
 audit(AUDIT_OS_SP_NOT_VULN);

if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows 10
  hotfix_is_vulnerable(os:"10", sp:0, file:"mshtml.dll", version:"11.0.10586.212", min_version:"11.0.10586.0", dir:"\system32", bulletin:bulletin, kb:"3147458") ||
  hotfix_is_vulnerable(os:"10", sp:0, file:"mshtml.dll", version:"11.0.10240.16769", min_version:"11.0.10240.16000", dir:"\system32", bulletin:bulletin, kb:"3147461") ||

  # Windows 8.1 / Windows Server 2012 R2
  # Internet Explorer 11
   hotfix_is_vulnerable(os:"6.3", sp:0, file:"mshtml.dll", version:"11.0.9600.18281", min_version:"11.0.9600.17000", dir:"\system32", bulletin:bulletin, kb:"3148198") ||

  # Windows Server 2012
  # Internet Explorer 10
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"mshtml.dll", version:"10.0.9200.22121", min_version:"10.0.9200.17000", dir:"\system32", bulletin:bulletin, kb:"4014661") ||

  # Windows 7 / Server 2008 R2
  # Internet Explorer 11
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"mshtml.dll", version:"11.0.9600.18281", min_version:"11.0.9600.17000", dir:"\system32", bulletin:bulletin, kb:"3148198") ||

  # Vista / Windows Server 2008
  # Internet Explorer 9
  hotfix_is_vulnerable(os:"6.0", sp:2, arch:"x86", file:"mshtml.dll", version:"9.0.8112.20888", min_version:"9.0.8112.20000", dir:"\system32", bulletin:bulletin, kb:"3148198") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, arch:"x64", file:"mshtml.dll", version:"9.0.8112.20885", min_version:"9.0.8112.20000", dir:"\system32", bulletin:bulletin, kb:"3148198") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, arch:"x86", file:"mshtml.dll", version:"9.0.8112.16773", min_version:"9.0.8112.16000", dir:"\system32", bulletin:bulletin, kb:"3148198") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, arch:"x64", file:"mshtml.dll", version:"9.0.8112.16770", min_version:"9.0.8112.16000", dir:"\system32", bulletin:bulletin, kb:"3148198")
)
{
  set_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
