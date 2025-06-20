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
  script_id(172531);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/17");

  script_cve_id(
    "CVE-2023-21708",
    "CVE-2023-23385",
    "CVE-2023-23394",
    "CVE-2023-23401",
    "CVE-2023-23402",
    "CVE-2023-23403",
    "CVE-2023-23404",
    "CVE-2023-23405",
    "CVE-2023-23406",
    "CVE-2023-23407",
    "CVE-2023-23409",
    "CVE-2023-23410",
    "CVE-2023-23412",
    "CVE-2023-23413",
    "CVE-2023-23414",
    "CVE-2023-23415",
    "CVE-2023-23416",
    "CVE-2023-23420",
    "CVE-2023-23421",
    "CVE-2023-23422",
    "CVE-2023-23423",
    "CVE-2023-24856",
    "CVE-2023-24857",
    "CVE-2023-24858",
    "CVE-2023-24859",
    "CVE-2023-24861",
    "CVE-2023-24862",
    "CVE-2023-24863",
    "CVE-2023-24864",
    "CVE-2023-24865",
    "CVE-2023-24866",
    "CVE-2023-24867",
    "CVE-2023-24868",
    "CVE-2023-24869",
    "CVE-2023-24870",
    "CVE-2023-24872",
    "CVE-2023-24876",
    "CVE-2023-24906",
    "CVE-2023-24907",
    "CVE-2023-24908",
    "CVE-2023-24909",
    "CVE-2023-24910",
    "CVE-2023-24911",
    "CVE-2023-24913"
  );
  script_xref(name:"MSKB", value:"5023752");
  script_xref(name:"MSKB", value:"5023756");
  script_xref(name:"MSFT", value:"MS23-5023752");
  script_xref(name:"MSFT", value:"MS23-5023756");
  script_xref(name:"IAVA", value:"2023-A-0135-S");
  script_xref(name:"IAVA", value:"2023-A-0139-S");

  script_name(english:"KB5023752: Windows Server 2012 Security Update (March 2023)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security update 5023752. It is, therefore, affected by multiple vulnerabilities

  - Internet Control Message Protocol (ICMP) Remote Code Execution Vulnerability (CVE-2023-23415)

  - Remote Procedure Call Runtime Remote Code Execution Vulnerability (CVE-2023-21708, CVE-2023-23405,
    CVE-2023-24869, CVE-2023-24908)

  - Windows Point-to-Point Protocol over Ethernet (PPPoE) Elevation of Privilege Vulnerability
    (CVE-2023-23385)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/help/5023752");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/help/5023756");
  script_set_attribute(attribute:"solution", value:
"Apply Security Update 5023752 or Cumulative Update 5023756");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-23415");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows_server_2012");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

bulletin = 'MS23-03';
kbs = make_list(
  '5023756',
  '5023752'
);

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit('SMB/Registry/Enumerated');
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp_range(win8:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  smb_check_rollup(os:'6.2',
                   sp:0,
                   rollup_date:'03_2023',
                   bulletin:bulletin,
                   rollup_kb_list:[5023756, 5023752])
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
