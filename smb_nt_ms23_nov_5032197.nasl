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
  script_id(185576);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/17");

  script_cve_id(
    "CVE-2023-36017",
    "CVE-2023-36025",
    "CVE-2023-36028",
    "CVE-2023-36036",
    "CVE-2023-36392",
    "CVE-2023-36393",
    "CVE-2023-36394",
    "CVE-2023-36395",
    "CVE-2023-36397",
    "CVE-2023-36398",
    "CVE-2023-36400",
    "CVE-2023-36401",
    "CVE-2023-36402",
    "CVE-2023-36403",
    "CVE-2023-36404",
    "CVE-2023-36405",
    "CVE-2023-36408",
    "CVE-2023-36423",
    "CVE-2023-36424",
    "CVE-2023-36425",
    "CVE-2023-36428",
    "CVE-2023-36705",
    "CVE-2023-36719",
    "CVE-2024-21315"
  );
  script_xref(name:"MSKB", value:"5032197");
  script_xref(name:"MSFT", value:"MS23-5032197");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/12/05");
  script_xref(name:"IAVA", value:"2023-A-0638-S");
  script_xref(name:"IAVA", value:"2023-A-0636-S");
  script_xref(name:"IAVA", value:"2024-A-0105");

  script_name(english:"KB5032197: Windows 10 Version 1607 and Windows Server 2016 Security Update (November 2023)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security update 5032197. It is, therefore, affected by multiple vulnerabilities

  - Microsoft WDAC OLE DB provider for SQL Server Remote Code Execution Vulnerability (CVE-2023-36402)

  - Windows Pragmatic General Multicast (PGM) Remote Code Execution Vulnerability (CVE-2023-36397)

  - Microsoft Protected Extensible Authentication Protocol (PEAP) Remote Code Execution Vulnerability
    (CVE-2023-36028)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/help/5032197");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-21315");
  script_set_attribute(attribute:"solution", value:
"Apply Security Update 5032197");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-36402");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-36397");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/11/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/11/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows_server_2016");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows_10_1607");
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

bulletin = 'MS23-11';
kbs = make_list(
  '5032197'
);

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit('SMB/Registry/Enumerated');
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp_range(win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  smb_check_rollup(os:'10',
                   os_build:14393,
                   rollup_date:'11_2023',
                   bulletin:bulletin,
                   rollup_kb_list:[5032197])
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
