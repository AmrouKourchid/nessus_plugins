#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(31044);
 script_version("1.34");
 script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/07");

 script_cve_id(
  "CVE-2007-4790",
  "CVE-2007-5322",
  "CVE-2008-0076",
  "CVE-2008-0077",
  "CVE-2008-0078"
 );
 script_bugtraq_id(25571, 25977, 27666, 27668, 27689);
 script_xref(name:"MSFT", value:"MS08-010");
 script_xref(name:"MSKB", value:"944533");

 script_name(english:"MS08-010: Cumulative Security Update for Internet Explorer (944533)");
 script_summary(english:"Determines the presence of update 944533");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the web
client.");
 script_set_attribute(attribute:"description", value:
"The remote host is missing the IE cumulative security update 944533.

The remote version of IE is vulnerable to several flaws that could allow
an attacker to execute arbitrary code on the remote host.");
 script_set_attribute(attribute:"see_also", value:"https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2008/ms08-010");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP, 2003 and
Vista.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploited_by_malware", value:"true");
 script_cwe_id(78, 94, 119, 399);

 script_set_attribute(attribute:"vuln_publication_date", value:"2007/10/18");
 script_set_attribute(attribute:"patch_publication_date", value:"2008/02/12");
 script_set_attribute(attribute:"plugin_publication_date", value:"2008/02/12");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:ie:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:ie:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:ie:7");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2008-2025 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");

 script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
 script_require_keys("SMB/MS_Bulletin_Checks/Possible");
 script_require_ports(139, 445, 'Host/patch_management_checks');
 exit(0);
}


include("audit.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS08-010';
kb = '944533';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2k:'4,5', xp:'2', win2003:'1,2', vista:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  hotfix_is_vulnerable(os:"6.0", sp:0, file:"Mshtml.dll", version:"7.0.6000.20734", min_version:"7.0.6000.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:0, file:"Mshtml.dll", version:"7.0.6000.16609", dir:"\system32", bulletin:bulletin, kb:kb) ||

  hotfix_is_vulnerable(os:"5.2", sp:1, file:"Mshtml.dll", version:"6.0.3790.3064", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Mshtml.dll", version:"6.0.3790.4210", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.2", file:"Mshtml.dll", version:"7.0.6000.20733", min_version:"7.0.6000.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.2", file:"Mshtml.dll", version:"7.0.6000.16608", min_version:"7.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb) ||

  hotfix_is_vulnerable(os:"5.1", sp:2, file:"Mshtml.dll", version:"6.0.2900.3268", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.1", sp:2, file:"Mshtml.dll", version:"7.0.6000.20733", min_version:"7.0.6000.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.1", sp:2, file:"Mshtml.dll", version:"7.0.6000.16608", min_version:"7.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb) ||

  hotfix_is_vulnerable(os:"5.0", file:"Mshtml.dll", version:"6.0.2800.1607", min_version:"6.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.0", file:"Mshtml.dll", version:"5.0.3860.1000", dir:"\system32", bulletin:bulletin, kb:kb)
)
{
  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
