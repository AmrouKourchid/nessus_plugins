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
  script_id(164998);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/17");

  script_cve_id(
    "CVE-2022-23960",
    "CVE-2022-26928",
    "CVE-2022-30170",
    "CVE-2022-30196",
    "CVE-2022-30200",
    "CVE-2022-34718",
    "CVE-2022-34719",
    "CVE-2022-34720",
    "CVE-2022-34721",
    "CVE-2022-34722",
    "CVE-2022-34723",
    "CVE-2022-34725",
    "CVE-2022-34726",
    "CVE-2022-34727",
    "CVE-2022-34728",
    "CVE-2022-34729",
    "CVE-2022-34730",
    "CVE-2022-34731",
    "CVE-2022-34732",
    "CVE-2022-34733",
    "CVE-2022-34734",
    "CVE-2022-35803",
    "CVE-2022-35831",
    "CVE-2022-35832",
    "CVE-2022-35833",
    "CVE-2022-35834",
    "CVE-2022-35835",
    "CVE-2022-35836",
    "CVE-2022-35837",
    "CVE-2022-35838",
    "CVE-2022-35840",
    "CVE-2022-35841",
    "CVE-2022-37954",
    "CVE-2022-37955",
    "CVE-2022-37956",
    "CVE-2022-37957",
    "CVE-2022-37958",
    "CVE-2022-37969",
    "CVE-2022-38004",
    "CVE-2022-38005",
    "CVE-2022-38006"
  );
  script_xref(name:"MSKB", value:"5017328");
  script_xref(name:"MSFT", value:"MS22-5017328");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/10/05");
  script_xref(name:"IAVA", value:"2022-A-0369-S");
  script_xref(name:"IAVA", value:"2022-A-0368-S");
  script_xref(name:"CEA-ID", value:"CEA-2022-0042");

  script_name(english:"KB5017328: Windows 11 Security Update (September 2022)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security update 5017328. It is, therefore, affected by multiple vulnerabilities

  - Certain Arm Cortex and Neoverse processors through 2022-03-08 do not properly restrict cache speculation,
    aka Spectre-BHB. An attacker can leverage the shared branch history in the Branch History Buffer (BHB) to
    influence mispredicted branches. Then, cache allocation can allow the attacker to obtain sensitive
    information. (CVE-2022-23960)

  - Windows Photo Import API Elevation of Privilege Vulnerability (CVE-2022-26928)

  - Windows Credential Roaming Service Elevation of Privilege Vulnerability (CVE-2022-30170)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5017328");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/help/5017328");
  script_set_attribute(attribute:"solution", value:
"Apply Security Update 5017328");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-23960");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-34722");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows_11_21h2");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

bulletin = 'MS22-09';
kbs = make_list(
  '5017328'
);

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_NOTE);

get_kb_item_or_exit('SMB/Registry/Enumerated');
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp_range(win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  smb_check_rollup(os:'10',
                   os_build:22000,
                   rollup_date:'09_2022',
                   bulletin:bulletin,
                   rollup_kb_list:[5017328])
)
{
  replace_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_note();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, hotfix_get_audit_report());
}
