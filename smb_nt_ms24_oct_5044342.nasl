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
  script_id(208289);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/15");

  script_cve_id(
    "CVE-2024-37976",
    "CVE-2024-37979",
    "CVE-2024-37982",
    "CVE-2024-37983",
    "CVE-2024-38124",
    "CVE-2024-38149",
    "CVE-2024-38212",
    "CVE-2024-38261",
    "CVE-2024-38262",
    "CVE-2024-38265",
    "CVE-2024-43453",
    "CVE-2024-43456",
    "CVE-2024-43501",
    "CVE-2024-43506",
    "CVE-2024-43509",
    "CVE-2024-43514",
    "CVE-2024-43515",
    "CVE-2024-43517",
    "CVE-2024-43518",
    "CVE-2024-43519",
    "CVE-2024-43520",
    "CVE-2024-43521",
    "CVE-2024-43532",
    "CVE-2024-43534",
    "CVE-2024-43535",
    "CVE-2024-43541",
    "CVE-2024-43544",
    "CVE-2024-43545",
    "CVE-2024-43547",
    "CVE-2024-43549",
    "CVE-2024-43550",
    "CVE-2024-43553",
    "CVE-2024-43556",
    "CVE-2024-43560",
    "CVE-2024-43563",
    "CVE-2024-43564",
    "CVE-2024-43567",
    "CVE-2024-43570",
    "CVE-2024-43572",
    "CVE-2024-43583",
    "CVE-2024-43589",
    "CVE-2024-43592",
    "CVE-2024-43593",
    "CVE-2024-43599",
    "CVE-2024-43607",
    "CVE-2024-43608",
    "CVE-2024-43611"
  );
  script_xref(name:"MSKB", value:"5044342");
  script_xref(name:"MSFT", value:"MS24-5044342");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/10/29");
  script_xref(name:"IAVA", value:"2024-A-0631-S");
  script_xref(name:"IAVA", value:"2024-A-0630-S");

  script_name(english:"KB5044342: Windows Server 2012 Security Update (October 2024)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security update 5044342. It is, therefore, affected by multiple vulnerabilities

  - Windows Routing and Remote Access Service (RRAS) Remote Code Execution Vulnerability (CVE-2024-38212,
    CVE-2024-38261, CVE-2024-38265, CVE-2024-43453, CVE-2024-43549, CVE-2024-43564, CVE-2024-43589,
    CVE-2024-43592, CVE-2024-43593, CVE-2024-43607, CVE-2024-43608, CVE-2024-43611)

  - Windows Netlogon Elevation of Privilege Vulnerability (CVE-2024-38124)

  - Remote Desktop Client Remote Code Execution Vulnerability (CVE-2024-43599)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/help/5044342");
  script_set_attribute(attribute:"solution", value:
"Apply Security Update 5044342");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-43608");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-38124");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows_server_2012");
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

var bulletin = 'MS24-10';
var kbs = make_list(
  '5044342'
);

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit('SMB/Registry/Enumerated');
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp_range(win8:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

var share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  smb_check_rollup(os:'6.2',
                   sp:0,
                   rollup_date:'10_2024',
                   bulletin:bulletin,
                   rollup_kb_list:[5044342])
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
