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
  script_id(216129);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/21");

  script_cve_id(
    "CVE-2025-21181",
    "CVE-2025-21184",
    "CVE-2025-21190",
    "CVE-2025-21200",
    "CVE-2025-21201",
    "CVE-2025-21212",
    "CVE-2025-21216",
    "CVE-2025-21254",
    "CVE-2025-21337",
    "CVE-2025-21347",
    "CVE-2025-21349",
    "CVE-2025-21350",
    "CVE-2025-21351",
    "CVE-2025-21352",
    "CVE-2025-21358",
    "CVE-2025-21359",
    "CVE-2025-21367",
    "CVE-2025-21368",
    "CVE-2025-21369",
    "CVE-2025-21371",
    "CVE-2025-21373",
    "CVE-2025-21375",
    "CVE-2025-21376",
    "CVE-2025-21377",
    "CVE-2025-21391",
    "CVE-2025-21406",
    "CVE-2025-21407",
    "CVE-2025-21414",
    "CVE-2025-21418",
    "CVE-2025-21419",
    "CVE-2025-21420"
  );
  script_xref(name:"MSKB", value:"5051974");
  script_xref(name:"MSFT", value:"MS25-5051974");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2025/03/04");
  script_xref(name:"IAVA", value:"2025-A-0109-S");
  script_xref(name:"IAVA", value:"2025-A-0110-S");

  script_name(english:"KB5051974: Windows 10 version 21H2 / Windows 10 Version 22H2 Security Update (February 2025)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security update 5051974. It is, therefore, affected by multiple vulnerabilities

  - Windows Telephony Service Remote Code Execution Vulnerability (CVE-2025-21190, CVE-2025-21200,
    CVE-2025-21371, CVE-2025-21406, CVE-2025-21407)

  - Microsoft Digest Authentication Remote Code Execution Vulnerability (CVE-2025-21368, CVE-2025-21369)

  - Windows Telephony Server Remote Code Execution Vulnerability (CVE-2025-21201)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/help/5051974");
  script_set_attribute(attribute:"solution", value:
"Apply Security Update 5051974");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-21407");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/02/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/02/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows_10_21h2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows_10_22h2");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

var bulletin = 'MS25-02';
var kbs = make_list(
  '5051974'
);

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit('SMB/Registry/Enumerated');
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp_range(win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

var share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

var os_name = get_kb_item("SMB/ProductName");

if ( (("enterprise" >< tolower(os_name) && "ltsc" >< tolower(os_name))
  && 
  smb_check_rollup(os:'10',
                   os_build:19044,
                   rollup_date:'02_2025',
                   bulletin:bulletin,
                   rollup_kb_list:[5051974])
)
|| 
smb_check_rollup(os:'10',
                   os_build:19045,
                   rollup_date:'02_2025',
                   bulletin:bulletin,
                   rollup_kb_list:[5051974])
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
