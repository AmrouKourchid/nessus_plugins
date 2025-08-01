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
  script_id(171453);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/17");

  script_cve_id(
    "CVE-2023-21684",
    "CVE-2023-21685",
    "CVE-2023-21686",
    "CVE-2023-21688",
    "CVE-2023-21689",
    "CVE-2023-21690",
    "CVE-2023-21691",
    "CVE-2023-21692",
    "CVE-2023-21693",
    "CVE-2023-21694",
    "CVE-2023-21695",
    "CVE-2023-21697",
    "CVE-2023-21699",
    "CVE-2023-21700",
    "CVE-2023-21701",
    "CVE-2023-21702",
    "CVE-2023-21797",
    "CVE-2023-21798",
    "CVE-2023-21799",
    "CVE-2023-21801",
    "CVE-2023-21802",
    "CVE-2023-21804",
    "CVE-2023-21805",
    "CVE-2023-21811",
    "CVE-2023-21812",
    "CVE-2023-21813",
    "CVE-2023-21816",
    "CVE-2023-21817",
    "CVE-2023-21818",
    "CVE-2023-21820",
    "CVE-2023-21822",
    "CVE-2023-21823",
    "CVE-2023-23376"
  );
  script_xref(name:"MSKB", value:"5022894");
  script_xref(name:"MSKB", value:"5022899");
  script_xref(name:"MSFT", value:"MS23-5022894");
  script_xref(name:"MSFT", value:"MS23-5022899");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/03/07");
  script_xref(name:"IAVA", value:"2023-A-0083-S");
  script_xref(name:"IAVA", value:"2023-A-0090-S");

  script_name(english:"KB5022894: Windows 8.1 Embedded and Windows Server 2012 R2 Security Update (February 2023)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security update 5022894. It is, therefore, affected by multiple vulnerabilities

  - Microsoft PostScript Printer Driver Remote Code Execution Vulnerability (CVE-2023-21684, CVE-2023-21801)

  - Microsoft WDAC OLE DB provider for SQL Server Remote Code Execution Vulnerability (CVE-2023-21685,
    CVE-2023-21686, CVE-2023-21799)

  - Microsoft Protected Extensible Authentication Protocol (PEAP) Remote Code Execution Vulnerability (CVE-2023-21689)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/help/5022894");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/help/5022899");
  script_set_attribute(attribute:"solution", value:
"Apply Security Update 5022894 or Cumulative Update 5022899");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-21799");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-21692");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows_8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows_server_2012:r2");
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

bulletin = 'MS23-02';
kbs = make_list(
  '5022899',
  '5022894'
);

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit('SMB/Registry/Enumerated');
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp_range(win81:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

# Win 8.1 (not Embedded) is EOS since Jan 10, 2023
var productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ("8.1" >< productname && "Embedded" >!< productname) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  smb_check_rollup(os:'6.3',
                   sp:0,
                   rollup_date:'02_2023',
                   bulletin:bulletin,
                   rollup_kb_list:[5022899, 5022894])
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
