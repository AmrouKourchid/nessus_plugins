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
  script_id(197016);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/25");

  script_cve_id(
    "CVE-2024-29994",
    "CVE-2024-29996",
    "CVE-2024-29997",
    "CVE-2024-29998",
    "CVE-2024-29999",
    "CVE-2024-30000",
    "CVE-2024-30001",
    "CVE-2024-30002",
    "CVE-2024-30003",
    "CVE-2024-30004",
    "CVE-2024-30005",
    "CVE-2024-30006",
    "CVE-2024-30008",
    "CVE-2024-30009",
    "CVE-2024-30012",
    "CVE-2024-30014",
    "CVE-2024-30015",
    "CVE-2024-30016",
    "CVE-2024-30017",
    "CVE-2024-30018",
    "CVE-2024-30020",
    "CVE-2024-30021",
    "CVE-2024-30022",
    "CVE-2024-30023",
    "CVE-2024-30024",
    "CVE-2024-30025",
    "CVE-2024-30027",
    "CVE-2024-30028",
    "CVE-2024-30029",
    "CVE-2024-30031",
    "CVE-2024-30032",
    "CVE-2024-30034",
    "CVE-2024-30035",
    "CVE-2024-30037",
    "CVE-2024-30038",
    "CVE-2024-30039",
    "CVE-2024-30040",
    "CVE-2024-30049",
    "CVE-2024-30050",
    "CVE-2024-30051"
  );
  script_xref(name:"MSKB", value:"5037771");
  script_xref(name:"MSFT", value:"MS24-5037771");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/06/04");
  script_xref(name:"IAVA", value:"2024-A-0281-S");
  script_xref(name:"IAVA", value:"2024-A-0282-S");

  script_name(english:"KB5037771: Windows 11 version 22H2 / Windows 11 version 23H2 Security Update (May 2024)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security update 5037771. It is, therefore, affected by multiple vulnerabilities

  - Windows MSHTML Platform Security Feature Bypass Vulnerability (CVE-2024-30040)

  - Windows Common Log File System Driver Elevation of Privilege Vulnerability (CVE-2024-29996,
    CVE-2024-30025, CVE-2024-30037)

  - Windows Mobile Broadband Driver Remote Code Execution Vulnerability (CVE-2024-29997, CVE-2024-29998,
    CVE-2024-29999, CVE-2024-30000, CVE-2024-30001, CVE-2024-30002, CVE-2024-30003, CVE-2024-30004,
    CVE-2024-30005, CVE-2024-30012, CVE-2024-30021)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/help/5037771");
  script_set_attribute(attribute:"solution", value:
"Apply Security Update 5037771");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-30040");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Windows Kernel Time of Check Time of Use LPE in AuthzBasepCopyoutInternalSecurityAttributes');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows_11_22h2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows_11_23h2");
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

bulletin = 'MS24-05';
kbs = make_list(
  '5037771'
);

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit('SMB/Registry/Enumerated');
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp_range(win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  smb_check_rollup(os:'10',
                   os_build:22621,
                   rollup_date:'05_2024',
                   bulletin:bulletin,
                   rollup_kb_list:[5037771])
||
  smb_check_rollup(os:'10',
                   os_build:22631,
                   rollup_date:'05_2024',
                   bulletin:bulletin,
                   rollup_kb_list:[5037771])
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
