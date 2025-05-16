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
  script_id(191941);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/09");

  script_cve_id(
    "CVE-2023-28746",
    "CVE-2024-21407",
    "CVE-2024-21408",
    "CVE-2024-21427",
    "CVE-2024-21429",
    "CVE-2024-21430",
    "CVE-2024-21432",
    "CVE-2024-21433",
    "CVE-2024-21436",
    "CVE-2024-21437",
    "CVE-2024-21438",
    "CVE-2024-21439",
    "CVE-2024-21440",
    "CVE-2024-21441",
    "CVE-2024-21444",
    "CVE-2024-21446",
    "CVE-2024-21450",
    "CVE-2024-21451",
    "CVE-2024-26159",
    "CVE-2024-26161",
    "CVE-2024-26162",
    "CVE-2024-26166",
    "CVE-2024-26169",
    "CVE-2024-26173",
    "CVE-2024-26174",
    "CVE-2024-26176",
    "CVE-2024-26177",
    "CVE-2024-26178",
    "CVE-2024-26181"
  );
  script_xref(name:"MSKB", value:"5035858");
  script_xref(name:"MSFT", value:"MS24-5035858");
  script_xref(name:"IAVA", value:"2024-A-0149-S");
  script_xref(name:"IAVA", value:"2024-A-0148-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/07/04");

  script_name(english:"KB5035858: Windows 10 LTS 1507 Security Update (March 2024)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security update 5035858. It is, therefore, affected by multiple vulnerabilities

  - Microsoft WDAC OLE DB provider for SQL Server Remote Code Execution Vulnerability (CVE-2024-21441,
    CVE-2024-21444, CVE-2024-21450, CVE-2024-26161, CVE-2024-26166)

  - Windows USB Hub Driver Remote Code Execution Vulnerability (CVE-2024-21429)

  - Windows USB Attached SCSI (UAS) Protocol Remote Code Execution Vulnerability (CVE-2024-21430)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/help/5035858");
  script_set_attribute(attribute:"solution", value:
"Apply Security Update 5035858");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-26166");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-21407");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/03/12");

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

bulletin = 'MS24-03';
kbs = make_list(
  '5035858'
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
                   rollup_date:'03_2024',
                   bulletin:bulletin,
                   rollup_kb_list:[5035858])
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
