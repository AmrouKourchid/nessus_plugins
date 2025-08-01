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
  script_id(206893);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/11");

  script_cve_id(
    "CVE-2024-21416",
    "CVE-2024-30073",
    "CVE-2024-38014",
    "CVE-2024-38045",
    "CVE-2024-38046",
    "CVE-2024-38119",
    "CVE-2024-38217",
    "CVE-2024-38234",
    "CVE-2024-38235",
    "CVE-2024-38237",
    "CVE-2024-38238",
    "CVE-2024-38239",
    "CVE-2024-38240",
    "CVE-2024-38241",
    "CVE-2024-38242",
    "CVE-2024-38243",
    "CVE-2024-38244",
    "CVE-2024-38245",
    "CVE-2024-38246",
    "CVE-2024-38247",
    "CVE-2024-38248",
    "CVE-2024-38249",
    "CVE-2024-38250",
    "CVE-2024-38252",
    "CVE-2024-38253",
    "CVE-2024-38254",
    "CVE-2024-38257",
    "CVE-2024-38259",
    "CVE-2024-43461"
  );
  script_xref(name:"MSKB", value:"5043067");
  script_xref(name:"MSFT", value:"MS24-5043067");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/10/07");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/10/01");
  script_xref(name:"IAVA", value:"2024-A-0575-S");
  script_xref(name:"IAVA", value:"2024-A-0576-S");

  script_name(english:"KB5043067: Windows 11 version 21H2 Security Update (September 2024)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security update 5043067. It is, therefore, affected by multiple vulnerabilities

  - Windows MSHTML Platform Spoofing Vulnerability (CVE-2024-43461)

  - Microsoft Management Console Remote Code Execution Vulnerability (CVE-2024-38259)

  - Windows Remote Access Connection Manager Elevation of Privilege Vulnerability (CVE-2024-38240)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/help/5043067");
  script_set_attribute(attribute:"solution", value:
"Apply Security Update 5043067");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-43461");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-38240");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/09/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows_11_21h2");
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

bulletin = 'MS24-09';
kbs = make_list(
  '5043067'
);

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit('SMB/Registry/Enumerated');
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp_range(win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  smb_check_rollup(os:'10',
                   os_build:22000,
                   rollup_date:'09_2024',
                   bulletin:bulletin,
                   rollup_kb_list:[5043067])
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
