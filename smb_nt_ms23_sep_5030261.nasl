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
  script_id(181299);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/24");

  script_cve_id(
    "CVE-2023-36801",
    "CVE-2023-36804",
    "CVE-2023-38139",
    "CVE-2023-38141",
    "CVE-2023-38142",
    "CVE-2023-38143",
    "CVE-2023-38144",
    "CVE-2023-38149",
    "CVE-2023-38152",
    "CVE-2023-38160",
    "CVE-2023-38161"
  );
  script_xref(name:"MSKB", value:"5030261");
  script_xref(name:"MSKB", value:"5030265");
  script_xref(name:"MSFT", value:"MS23-5030261");
  script_xref(name:"MSFT", value:"MS23-5030265");
  script_xref(name:"IAVA", value:"2023-A-0472-S");
  script_xref(name:"IAVA", value:"2023-A-0471-S");

  script_name(english:"KB5030261: Windows Server 2008 R2 Security Update (September 2023)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security update 5030261. It is, therefore, affected by multiple vulnerabilities

  - Windows GDI Elevation of Privilege Vulnerability (CVE-2023-36804, CVE-2023-38161)

  - DHCP Server Service Information Disclosure Vulnerability (CVE-2023-36801, CVE-2023-38152)

  - Windows TCP/IP Denial of Service Vulnerability (CVE-2023-38149)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/help/5030261");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/help/5030265");
  script_set_attribute(attribute:"solution", value:
"Apply Security Update 5030261 or Cumulative Update 5030265");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-38161");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/09/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/09/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/12");

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

bulletin = 'MS23-09';
kbs = make_list(
  '5030265',
  '5030261'
);

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit('SMB/Registry/Enumerated');
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp_range(win7:'1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

var os_name = get_kb_item("SMB/ProductName");

if (("windows server 2008 r2" >< tolower(os_name)) &&
  smb_check_rollup(os:'6.1',
                   sp:1,
                   rollup_date:'09_2023',
                   bulletin:bulletin,
                   rollup_kb_list:[5030265, 5030261])
)
{
  replace_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, hotfix_get_audit_report());
}
