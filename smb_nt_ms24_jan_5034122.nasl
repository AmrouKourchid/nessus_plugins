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
  script_id(187795);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/17");

  script_cve_id(
    "CVE-2022-35737",
    "CVE-2024-20652",
    "CVE-2024-20653",
    "CVE-2024-20654",
    "CVE-2024-20657",
    "CVE-2024-20658",
    "CVE-2024-20660",
    "CVE-2024-20661",
    "CVE-2024-20663",
    "CVE-2024-20664",
    "CVE-2024-20666",
    "CVE-2024-20674",
    "CVE-2024-20680",
    "CVE-2024-20681",
    "CVE-2024-20682",
    "CVE-2024-20683",
    "CVE-2024-20687",
    "CVE-2024-20690",
    "CVE-2024-20691",
    "CVE-2024-20692",
    "CVE-2024-20694",
    "CVE-2024-20696",
    "CVE-2024-20698",
    "CVE-2024-20699",
    "CVE-2024-20700",
    "CVE-2024-21305",
    "CVE-2024-21306",
    "CVE-2024-21307",
    "CVE-2024-21310",
    "CVE-2024-21311",
    "CVE-2024-21313",
    "CVE-2024-21314",
    "CVE-2024-21316",
    "CVE-2024-21320"
  );
  script_xref(name:"MSKB", value:"5034122");
  script_xref(name:"MSFT", value:"MS24-5034122");
  script_xref(name:"IAVA", value:"2024-A-0015-S");
  script_xref(name:"IAVA", value:"2024-A-0016-S");

  script_name(english:"KB5034122: Windows 10 Version 21H2 / Windows 10 Version 22H2 Security Update (January 2024)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security update 5034122. It is, therefore, affected by multiple vulnerabilities

  - Microsoft ODBC Driver Remote Code Execution Vulnerability (CVE-2024-20654)

  - BitLocker Security Feature Bypass Vulnerability (CVE-2024-20666)

  - Windows Kerberos Security Feature Bypass Vulnerability (CVE-2024-20674)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/help/5034122");
  script_set_attribute(attribute:"solution", value:
"Apply Security Update 5034122");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20674");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/08/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows_10_21h2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows_10_22h2");
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

bulletin = 'MS24-01';
kbs = make_list(
  '5034122'
);

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit('SMB/Registry/Enumerated');
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp_range(win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

var os_name = get_kb_item("SMB/ProductName");

if ( (("enterprise" >< tolower(os_name) || "education" >< tolower(os_name))
  && 
  smb_check_rollup(os:'10',
                   os_build:19044,
                   rollup_date:'01_2024',
                   bulletin:bulletin,
                   rollup_kb_list:[5034122])
  )
  || 
  smb_check_rollup(os:'10',
                   os_build:19045,
                   rollup_date:'01_2024',
                   bulletin:bulletin,
                   rollup_kb_list:[5034122])
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
