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
  script_id(205464);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/06");

  script_cve_id(
    "CVE-2024-29995",
    "CVE-2024-37968",
    "CVE-2024-38063",
    "CVE-2024-38114",
    "CVE-2024-38115",
    "CVE-2024-38116",
    "CVE-2024-38117",
    "CVE-2024-38118",
    "CVE-2024-38120",
    "CVE-2024-38121",
    "CVE-2024-38122",
    "CVE-2024-38125",
    "CVE-2024-38128",
    "CVE-2024-38130",
    "CVE-2024-38131",
    "CVE-2024-38134",
    "CVE-2024-38140",
    "CVE-2024-38144",
    "CVE-2024-38151",
    "CVE-2024-38152",
    "CVE-2024-38153",
    "CVE-2024-38154",
    "CVE-2024-38180",
    "CVE-2024-38193",
    "CVE-2024-38196",
    "CVE-2024-38198",
    "CVE-2024-38199",
    "CVE-2024-38214"
  );
  script_xref(name:"MSKB", value:"5041850");
  script_xref(name:"MSFT", value:"MS24-5041850");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/09/03");
  script_xref(name:"IAVA", value:"2024-A-0500-S");
  script_xref(name:"IAVA", value:"2024-A-0499-S");

  script_name(english:"KB5041850: Windows Server 2008 Security Update (August 2024)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security update 5041850. It is, therefore, affected by multiple vulnerabilities

  - Windows Line Printer Daemon (LPD) Service Remote Code Execution Vulnerability (CVE-2024-38199)

  - Windows Reliable Multicast Transport Driver (RMCAST) Remote Code Execution Vulnerability (CVE-2024-38140)

  - Windows TCP/IP Remote Code Execution Vulnerability (CVE-2024-38063)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/help/5041850");
  script_set_attribute(attribute:"solution", value:
"Apply Security Update 5041850");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-38199");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/08/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows_server_2008");
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

bulletin = 'MS24-08';
kbs = make_list(
  '5041850'
);

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit('SMB/Registry/Enumerated');
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp_range(vista:'2') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  smb_check_rollup(os:'6.0',
                   sp:2,
                   rollup_date:'08_2024',
                   bulletin:bulletin,
                   rollup_kb_list:[5041850])
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
