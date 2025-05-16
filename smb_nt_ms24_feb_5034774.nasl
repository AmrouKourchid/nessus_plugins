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
  script_id(190492);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/17");

  script_cve_id(
    "CVE-2024-21340",
    "CVE-2024-21343",
    "CVE-2024-21344",
    "CVE-2024-21347",
    "CVE-2024-21348",
    "CVE-2024-21349",
    "CVE-2024-21350",
    "CVE-2024-21351",
    "CVE-2024-21352",
    "CVE-2024-21354",
    "CVE-2024-21355",
    "CVE-2024-21356",
    "CVE-2024-21357",
    "CVE-2024-21358",
    "CVE-2024-21359",
    "CVE-2024-21360",
    "CVE-2024-21361",
    "CVE-2024-21362",
    "CVE-2024-21363",
    "CVE-2024-21365",
    "CVE-2024-21366",
    "CVE-2024-21367",
    "CVE-2024-21368",
    "CVE-2024-21369",
    "CVE-2024-21370",
    "CVE-2024-21371",
    "CVE-2024-21372",
    "CVE-2024-21375",
    "CVE-2024-21377",
    "CVE-2024-21391",
    "CVE-2024-21405",
    "CVE-2024-21406",
    "CVE-2024-21420"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/03/05");
  script_xref(name:"MSKB", value:"5034774");
  script_xref(name:"MSFT", value:"MS24-5034774");
  script_xref(name:"IAVA", value:"2024-A-0092-S");
  script_xref(name:"IAVA", value:"2024-A-0091-S");

  script_name(english:"KB5034774: Windows 10 LTS 1507 Security Update (February 2024)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security update 5034774. It is, therefore, affected by multiple vulnerabilities

  - Microsoft WDAC OLE DB provider for SQL Server Remote Code Execution Vulnerability (CVE-2024-21350,
    CVE-2024-21352, CVE-2024-21358, CVE-2024-21359, CVE-2024-21360, CVE-2024-21361, CVE-2024-21365,
    CVE-2024-21366, CVE-2024-21367, CVE-2024-21368, CVE-2024-21369, CVE-2024-21370, CVE-2024-21375,
    CVE-2024-21391, CVE-2024-21420)

  - Windows Kernel Information Disclosure Vulnerability (CVE-2024-21340)

  - Microsoft ActiveX Data Objects Remote Code Execution Vulnerability (CVE-2024-21349)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/help/5034774");
  script_set_attribute(attribute:"solution", value:
"Apply Security Update 5034774");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-21420");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows_10_1507");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

bulletin = 'MS24-02';
kbs = make_list(
  '5034774'
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
                   rollup_date:'02_2024',
                   bulletin:bulletin,
                   rollup_kb_list:[5034774])
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
