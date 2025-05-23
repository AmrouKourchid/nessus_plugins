#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94643);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/07");

  script_cve_id(
    "CVE-2016-7195",
    "CVE-2016-7196",
    "CVE-2016-7198",
    "CVE-2016-7199",
    "CVE-2016-7227",
    "CVE-2016-7239",
    "CVE-2016-7241"
  );
  script_bugtraq_id(
    94051,
    94052,
    94053,
    94055,
    94057,
    94059,
    94065
  );
  script_xref(name:"MSFT", value:"MS16-142");
  script_xref(name:"MSKB", value:"3197655");
  script_xref(name:"MSKB", value:"3197867");
  script_xref(name:"MSKB", value:"3197868");
  script_xref(name:"MSKB", value:"3197873");
  script_xref(name:"MSKB", value:"3197874");
  script_xref(name:"MSKB", value:"3197876");
  script_xref(name:"MSKB", value:"3197877");
  script_xref(name:"MSKB", value:"3198585");
  script_xref(name:"MSKB", value:"3198586");
  script_xref(name:"MSKB", value:"3200970");

  script_name(english:"MS16-142: Cumulative Security Update for Internet Explorer (3198467)");
  script_summary(english:"Checks the version of mshtml.dll or the installed rollup.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a web browser installed that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Internet Explorer installed on the remote Windows host
is missing Cumulative Security Update 3198467. It is, therefore,
affected by multiple vulnerabilities, the majority of which are remote
code execution vulnerabilities. An unauthenticated, remote attacker
can exploit these vulnerabilities by convincing a user to visit a
specially crafted website, resulting in the execution of arbitrary
code in the context of the current user.");
  script_set_attribute(attribute:"see_also", value:"https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2016/ms16-142");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Internet Explorer 9, 10,
and 11.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-7241");
  script_set_attribute(attribute: "cvss3_score_source", value: "manual");
  script_set_attribute(attribute:"cvss3_score_rationale", value:"Scoring adjustsed to align with CVSS 3.1 attack complexity guidance.");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/11/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:ie");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:ie:9");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2016-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl", "smb_check_rollup.nasl");
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

bulletin = 'MS16-142';
kbs = make_list(
  '3197655',
  '3197867',
  '3197868',
  '3197873',
  '3197874',
  '3197876',
  '3197877',
  '3198585',
  '3198586',
  '3200970'  
);

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
  # Windows 10 1607
  smb_check_rollup(os:"10", sp:0, os_build:"14393", rollup_date: "11_2016", bulletin:bulletin, rollup_kb_list:make_list(3198585)) ||
  # Windows 10 1511
  smb_check_rollup(os:"10", sp:0, os_build:"10586", rollup_date: "11_2016", bulletin:bulletin, rollup_kb_list:make_list(3198586)) ||
  # Windows 10
  smb_check_rollup(os:"10", sp:0, os_build:"10240", rollup_date: "11_2016", bulletin:bulletin, rollup_kb_list:make_list(3200970)) ||

  # Windows 8.1 / Windows Server 2012 R2
  # Internet Explorer 11
  smb_check_rollup(os:"6.3", sp:0, rollup_date: "11_2016", bulletin:bulletin, rollup_kb_list:make_list(3197873, 3197874)) ||

  # Windows Server 2012
  # Internet Explorer 10
  smb_check_rollup(os:"6.2", sp:0, rollup_date: "11_2016", bulletin:bulletin, rollup_kb_list:make_list(3197876, 3197877)) ||

  # Windows 7 / Server 2008 R2
  # Internet Explorer 11
  smb_check_rollup(os:"6.1", sp:1, rollup_date: "11_2016", bulletin:bulletin, rollup_kb_list:make_list(3197867, 3197868)) ||

  # Vista / Windows Server 2008
  # Internet Explorer 9
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"mshtml.dll", version:"9.0.8112.20951", min_version:"9.0.8112.20000", dir:"\system32", bulletin:bulletin, kb:"3197655") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"mshtml.dll", version:"9.0.8112.16834", min_version:"9.0.8112.16000", dir:"\system32", bulletin:bulletin, kb:"3197655")
)
{
  set_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, hotfix_get_audit_report());
}
