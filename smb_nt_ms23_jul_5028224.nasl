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
  script_id(178168);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/17");

  script_cve_id(
    "CVE-2023-21526",
    "CVE-2023-32033",
    "CVE-2023-32034",
    "CVE-2023-32035",
    "CVE-2023-32038",
    "CVE-2023-32042",
    "CVE-2023-32043",
    "CVE-2023-32044",
    "CVE-2023-32045",
    "CVE-2023-32046",
    "CVE-2023-32050",
    "CVE-2023-32053",
    "CVE-2023-32054",
    "CVE-2023-32055",
    "CVE-2023-32057",
    "CVE-2023-33154",
    "CVE-2023-33163",
    "CVE-2023-33164",
    "CVE-2023-33166",
    "CVE-2023-33167",
    "CVE-2023-33168",
    "CVE-2023-33169",
    "CVE-2023-33172",
    "CVE-2023-33173",
    "CVE-2023-33174",
    "CVE-2023-35297",
    "CVE-2023-35299",
    "CVE-2023-35300",
    "CVE-2023-35303",
    "CVE-2023-35309",
    "CVE-2023-35310",
    "CVE-2023-35312",
    "CVE-2023-35314",
    "CVE-2023-35316",
    "CVE-2023-35318",
    "CVE-2023-35319",
    "CVE-2023-35321",
    "CVE-2023-35322",
    "CVE-2023-35328",
    "CVE-2023-35330",
    "CVE-2023-35332",
    "CVE-2023-35338",
    "CVE-2023-35340",
    "CVE-2023-35341",
    "CVE-2023-35342",
    "CVE-2023-35344",
    "CVE-2023-35345",
    "CVE-2023-35346",
    "CVE-2023-35350",
    "CVE-2023-35351",
    "CVE-2023-35365",
    "CVE-2023-35366",
    "CVE-2023-35367",
    "CVE-2023-36874"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/08/01");
  script_xref(name:"MSKB", value:"5028224");
  script_xref(name:"MSKB", value:"5028240");
  script_xref(name:"MSFT", value:"MS23-5028224");
  script_xref(name:"MSFT", value:"MS23-5028240");
  script_xref(name:"IAVA", value:"2023-A-0347-S");
  script_xref(name:"IAVA", value:"2023-A-0345-S");

  script_name(english:"KB5028224: Windows Server 2008 R2 Security Update (July 2023)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security update 5028224. It is, therefore, affected by multiple vulnerabilities

  - Windows Routing and Remote Access Service (RRAS) Remote Code Execution Vulnerability (CVE-2023-35365,
    CVE-2023-35366, CVE-2023-35367)

  - Windows Netlogon Information Disclosure Vulnerability (CVE-2023-21526)

  - Microsoft Failover Cluster Remote Code Execution Vulnerability (CVE-2023-32033)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/help/5028224");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/help/5028240");
  script_set_attribute(attribute:"solution", value:
"Apply Security Update 5028224 or Cumulative Update 5028240");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-35367");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Microsoft Error Reporting Local Privilege Elevation Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/07/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/07/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows_server_2008:r2");
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

bulletin = 'MS23-07';
kbs = make_list(
  '5028240',
  '5028224'
);

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit('SMB/Registry/Enumerated');
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp_range(win7:'1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

var os_name = get_kb_item("SMB/ProductName");

if (("windows server 2008 r2" >< tolower(os_name)) && 
  smb_check_rollup(os:'6.1',
                   sp:1,
                   rollup_date:'07_2023',
                   bulletin:bulletin,
                   rollup_kb_list:[5028240, 5028224])
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
