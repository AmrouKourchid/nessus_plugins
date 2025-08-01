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
  script_id(182851);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/08");

  script_cve_id(
    "CVE-2023-29348",
    "CVE-2023-35349",
    "CVE-2023-36431",
    "CVE-2023-36434",
    "CVE-2023-36435",
    "CVE-2023-36436",
    "CVE-2023-36438",
    "CVE-2023-36557",
    "CVE-2023-36563",
    "CVE-2023-36564",
    "CVE-2023-36567",
    "CVE-2023-36570",
    "CVE-2023-36571",
    "CVE-2023-36572",
    "CVE-2023-36573",
    "CVE-2023-36574",
    "CVE-2023-36575",
    "CVE-2023-36576",
    "CVE-2023-36577",
    "CVE-2023-36578",
    "CVE-2023-36579",
    "CVE-2023-36581",
    "CVE-2023-36582",
    "CVE-2023-36583",
    "CVE-2023-36584",
    "CVE-2023-36585",
    "CVE-2023-36589",
    "CVE-2023-36590",
    "CVE-2023-36591",
    "CVE-2023-36592",
    "CVE-2023-36593",
    "CVE-2023-36594",
    "CVE-2023-36596",
    "CVE-2023-36598",
    "CVE-2023-36602",
    "CVE-2023-36603",
    "CVE-2023-36605",
    "CVE-2023-36606",
    "CVE-2023-36697",
    "CVE-2023-36698",
    "CVE-2023-36701",
    "CVE-2023-36702",
    "CVE-2023-36703",
    "CVE-2023-36706",
    "CVE-2023-36707",
    "CVE-2023-36709",
    "CVE-2023-36710",
    "CVE-2023-36711",
    "CVE-2023-36712",
    "CVE-2023-36713",
    "CVE-2023-36717",
    "CVE-2023-36718",
    "CVE-2023-36720",
    "CVE-2023-36721",
    "CVE-2023-36722",
    "CVE-2023-36723",
    "CVE-2023-36724",
    "CVE-2023-36725",
    "CVE-2023-36726",
    "CVE-2023-36729",
    "CVE-2023-36731",
    "CVE-2023-36732",
    "CVE-2023-36743",
    "CVE-2023-36776",
    "CVE-2023-36902",
    "CVE-2023-38159",
    "CVE-2023-38166",
    "CVE-2023-38171",
    "CVE-2023-41765",
    "CVE-2023-41766",
    "CVE-2023-41767",
    "CVE-2023-41768",
    "CVE-2023-41769",
    "CVE-2023-41770",
    "CVE-2023-41771",
    "CVE-2023-41772",
    "CVE-2023-41773",
    "CVE-2023-41774",
    "CVE-2023-44487"
  );
  script_xref(name:"MSKB", value:"5031364");
  script_xref(name:"MSFT", value:"MS23-5031364");
  script_xref(name:"IAVA", value:"2023-A-0552-S");
  script_xref(name:"IAVA", value:"2023-A-0553-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/12/07");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/10/31");
  script_xref(name:"CEA-ID", value:"CEA-2024-0004");
  script_xref(name:"IAVB", value:"2023-B-0083-S");

  script_name(english:"KB5031364: Windows Server 2022 / Azure Stack HCI 22H2 Security Update (October 2023)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security update 5031364. It is, therefore, affected by multiple vulnerabilities

  - The HTTP/2 protocol allows a denial of service (server resource consumption) because request cancellation
    can reset many streams quickly, as exploited in the wild in August through October 2023. (CVE-2023-44487)

  - Microsoft QUIC Denial of Service Vulnerability (CVE-2023-36435, CVE-2023-38171)
  
  - Microsoft WDAC OLE DB provider for SQL Server Remote Code Execution Vulnerability (CVE-2023-36577)

  - Windows IIS Server Elevation of Privilege Vulnerability (CVE-2023-36434)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/help/5031364");
  script_set_attribute(attribute:"solution", value:
"Apply Security Update 5031364");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-36577");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-36434");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:azure_stack_hci_22h2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows_server_2022");
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

bulletin = 'MS23-10';
kbs = make_list(
  '5031364'
);

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit('SMB/Registry/Enumerated');
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp_range(win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  smb_check_rollup(os:'10',
                   os_build:20348,
                   rollup_date:'10_2023',
                   bulletin:bulletin,
                   rollup_kb_list:[5031364])
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
