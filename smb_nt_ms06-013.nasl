#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(21210);
 script_version("1.45");
 script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/07");

 script_cve_id(
  "CVE-2006-1359",
  "CVE-2006-1245",
  "CVE-2006-1388",
  "CVE-2006-1185",
  "CVE-2006-1186",
  "CVE-2006-1188",
  "CVE-2006-1189",
  "CVE-2006-1190",
  "CVE-2006-1191",
  "CVE-2006-1192"
 );
 script_bugtraq_id(
  17131,
  17181,
  17196,
  17468,
  17460,
  17457,
  17455,
  17454,
  17453,
  17450
 );
 script_xref(name:"CERT", value:"876678");
 script_xref(name:"MSFT", value:"MS06-013");
 script_xref(name:"MSKB", value:"912812");

 script_name(english:"MS06-013: Cumulative Security Update for Internet Explorer (912812)");
 script_summary(english:"Determines the presence of update 912812");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the web
client.");
 script_set_attribute(attribute:"description", value:
"The remote host is missing IE Cumulative Security Update 912812.

The remote version of IE is vulnerable to several flaws that could allow
an attacker to execute arbitrary code on the remote host.");
 script_set_attribute(attribute:"see_also", value:"https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2006/ms06-013");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP and
2003.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploited_by_malware", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'MS06-013 Microsoft Internet Explorer createTextRange() Code Execution');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_cwe_id(94);

 script_set_attribute(attribute:"vuln_publication_date", value:"2006/03/13");
 script_set_attribute(attribute:"patch_publication_date", value:"2006/04/11");
 script_set_attribute(attribute:"plugin_publication_date", value:"2006/04/11");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:ie:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:ie:6");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2006-2025 Tenable Network Security, Inc.");
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

bulletin = 'MS06-013';
kb = '912812';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp_range(win2k:'4,5', xp:'1,2', win2003:'0,1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if ( hotfix_is_vulnerable(os:"5.2", sp:0, file:"Mshtml.dll", version:"6.0.3790.497", dir:"\system32", bulletin:bulletin, kb:kb) ||
     hotfix_is_vulnerable(os:"5.2", sp:1, file:"Mshtml.dll", version:"6.0.3790.2666", dir:"\system32", bulletin:bulletin, kb:kb) ||
     hotfix_is_vulnerable(os:"5.1", sp:1, file:"Mshtml.dll", version:"6.0.2800.1543", dir:"\system32", bulletin:bulletin, kb:kb) ||
     hotfix_is_vulnerable(os:"5.1", sp:2, file:"Mshtml.dll", version:"6.0.2900.2873", dir:"\system32", bulletin:bulletin, kb:kb) ||
     hotfix_is_vulnerable(os:"5.0", file:"Mshtml.dll", version:"6.0.2800.1543", min_version:"6.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb) ||
     hotfix_is_vulnerable(os:"5.0", file:"Mshtml.dll", version:"5.0.3839.2200", dir:"\system32", bulletin:bulletin, kb:kb) )
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
