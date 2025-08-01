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
  script_id(163048);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/17");

  script_cve_id(
    "CVE-2022-21845",
    "CVE-2022-22022",
    "CVE-2022-22023",
    "CVE-2022-22024",
    "CVE-2022-22025",
    "CVE-2022-22026",
    "CVE-2022-22027",
    "CVE-2022-22028",
    "CVE-2022-22029",
    "CVE-2022-22031",
    "CVE-2022-22034",
    "CVE-2022-22036",
    "CVE-2022-22037",
    "CVE-2022-22038",
    "CVE-2022-22039",
    "CVE-2022-22040",
    "CVE-2022-22041",
    "CVE-2022-22042",
    "CVE-2022-22043",
    "CVE-2022-22045",
    "CVE-2022-22047",
    "CVE-2022-22048",
    "CVE-2022-22049",
    "CVE-2022-22050",
    "CVE-2022-22711",
    "CVE-2022-27776",
    "CVE-2022-30202",
    "CVE-2022-30203",
    "CVE-2022-30205",
    "CVE-2022-30206",
    "CVE-2022-30208",
    "CVE-2022-30209",
    "CVE-2022-30211",
    "CVE-2022-30212",
    "CVE-2022-30213",
    "CVE-2022-30214",
    "CVE-2022-30215",
    "CVE-2022-30216",
    "CVE-2022-30220",
    "CVE-2022-30221",
    "CVE-2022-30222",
    "CVE-2022-30223",
    "CVE-2022-30224",
    "CVE-2022-30225",
    "CVE-2022-30226",
    "CVE-2022-33644"
  );
  script_xref(name:"MSKB", value:"5015807");
  script_xref(name:"MSFT", value:"MS22-5015807");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/08/02");
  script_xref(name:"IAVA", value:"2022-A-0272-S");
  script_xref(name:"IAVA", value:"2022-A-0273-S");
  script_xref(name:"CEA-ID", value:"CEA-2022-0026");

  script_name(english:"KB5015807: Windows 10 Version 20H2 / 21H1 / 21H2 Security Update (July 2022)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security update 5015807. It is, therefore, affected by multiple vulnerabilities:

  - A remote code execution vulnerability. An attacker can
    exploit this to bypass authentication and execute
    unauthorized arbitrary commands. (CVE-2022-22024,
    CVE-2022-22027, CVE-2022-22029, CVE-2022-22038,
    CVE-2022-22039, CVE-2022-30211, CVE-2022-30214,
    CVE-2022-30221, CVE-2022-30222)

  - A security feature bypass vulnerability exists. An
    attacker can exploit this and bypass the security
    feature and perform unauthorized actions compromising
    the integrity of the system/application.
    (CVE-2022-22023, CVE-2022-22048, CVE-2022-30203)

  - An elevation of privilege vulnerability. An attacker can
    exploit this to gain elevated privileges.
    (CVE-2022-22022, CVE-2022-22026, CVE-2022-22031,
    CVE-2022-22034, CVE-2022-22036, CVE-2022-22037,
    CVE-2022-22041, CVE-2022-22045, CVE-2022-22047,
    CVE-2022-22049, CVE-2022-22050, CVE-2022-30202,
    CVE-2022-30205, CVE-2022-30206, CVE-2022-30209,
    CVE-2022-30215, CVE-2022-30220, CVE-2022-30224,
    CVE-2022-30225, CVE-2022-30226)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5015807");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/help/5015807");
  script_set_attribute(attribute:"solution", value:
"Apply Security Update 5015807");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-30215");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-30221");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/07/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows_10_20h2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows_10_21h1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows_10_21h2");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

bulletin = 'MS22-07';
kbs = make_list(
  '5015807'
);

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit('SMB/Registry/Enumerated');
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp_range(win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

var share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

var os_name = get_kb_item("SMB/ProductName");

if (
    ( ("enterprise" >< tolower(os_name) || "education" >< tolower(os_name))
      &&
      smb_check_rollup(os:'10',
                    os_build:19042,
                    rollup_date:'07_2022',
                    bulletin:bulletin,
                    rollup_kb_list:[5015807]) 
    )
  ||
    smb_check_rollup(os:'10',
                    os_build:19043,
                    rollup_date:'07_2022',
                    bulletin:bulletin,
                    rollup_kb_list:[5015807])
  || 
    smb_check_rollup(os:'10',
                    os_build:19044,
                    rollup_date:'07_2022',
                    bulletin:bulletin,
                    rollup_kb_list:[5015807])
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
