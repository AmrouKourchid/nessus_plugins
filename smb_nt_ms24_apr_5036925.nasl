#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.

#
# The descriptive text and package checks in this plugin were
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
##

include('compat.inc');

if (description)
{
  script_id(193098);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/21");

  script_cve_id(
    "CVE-2024-20665",
    "CVE-2024-20669",
    "CVE-2024-20678",
    "CVE-2024-20693",
    "CVE-2024-26158",
    "CVE-2024-26168",
    "CVE-2024-26171",
    "CVE-2024-26175",
    "CVE-2024-26179",
    "CVE-2024-26180",
    "CVE-2024-26183",
    "CVE-2024-26189",
    "CVE-2024-26194",
    "CVE-2024-26200",
    "CVE-2024-26205",
    "CVE-2024-26207",
    "CVE-2024-26208",
    "CVE-2024-26209",
    "CVE-2024-26210",
    "CVE-2024-26211",
    "CVE-2024-26214",
    "CVE-2024-26217",
    "CVE-2024-26220",
    "CVE-2024-26228",
    "CVE-2024-26229",
    "CVE-2024-26230",
    "CVE-2024-26232",
    "CVE-2024-26234",
    "CVE-2024-26239",
    "CVE-2024-26240",
    "CVE-2024-26241",
    "CVE-2024-26242",
    "CVE-2024-26244",
    "CVE-2024-26245",
    "CVE-2024-26248",
    "CVE-2024-26250",
    "CVE-2024-26252",
    "CVE-2024-26253",
    "CVE-2024-28896",
    "CVE-2024-28897",
    "CVE-2024-28898",
    "CVE-2024-28900",
    "CVE-2024-28901",
    "CVE-2024-28902",
    "CVE-2024-28903",
    "CVE-2024-28919",
    "CVE-2024-28921",
    "CVE-2024-28922",
    "CVE-2024-28923",
    "CVE-2024-28924",
    "CVE-2024-28925",
    "CVE-2024-29050",
    "CVE-2024-29061",
    "CVE-2024-29062",
    "CVE-2024-29064"
  );
  script_xref(name:"MSKB", value:"5036925");
  script_xref(name:"MSFT", value:"MS24-5036925");
  script_xref(name:"IAVA", value:"2024-A-0227-S");
  script_xref(name:"IAVA", value:"2024-A-0228-S");

  script_name(english:"KB5036925: Windows 10 LTS 1507 Security Update (April 2024)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security update 5036925. It is, therefore, affected by multiple vulnerabilities

  - Microsoft WDAC SQL Server ODBC Driver Remote Code Execution Vulnerability (CVE-2024-26214)

  - Secure Boot Security Feature Bypass Vulnerability (CVE-2024-20669, CVE-2024-26168, CVE-2024-26171,
    CVE-2024-26175, CVE-2024-26180, CVE-2024-26189, CVE-2024-26194, CVE-2024-26240, CVE-2024-26250,
    CVE-2024-28896, CVE-2024-28897, CVE-2024-28898, CVE-2024-28903, CVE-2024-28919, CVE-2024-28921,
    CVE-2024-28922, CVE-2024-28923, CVE-2024-28924, CVE-2024-28925, CVE-2024-29061, CVE-2024-29062)

  - Windows rndismp6.sys Remote Code Execution Vulnerability (CVE-2024-26252, CVE-2024-26253)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/help/5036925");
  script_set_attribute(attribute:"solution", value:
"Apply Security Update 5036925");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-26205");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-29061");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows_10_1507");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_check_rollup.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('smb_func.inc');
include('smb_hotfixes.inc');
include('smb_hotfixes_fcheck.inc');
include('smb_reg_query.inc');

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

bulletin = 'MS24-04';
kbs = make_list(
  '5036925'
);

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit('SMB/Registry/Enumerated');
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp_range(win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  smb_check_rollup(os:'10',
                   os_build:10240,
                   rollup_date:'04_2024',
                   bulletin:bulletin,
                   rollup_kb_list:[5036925])
)
{
  replace_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, hotfix_get_audit_report());
}
