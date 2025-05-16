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
  script_id(202037);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/31");

  script_cve_id(
    "CVE-2024-3596",
    "CVE-2024-21417",
    "CVE-2024-26184",
    "CVE-2024-28899",
    "CVE-2024-30013",
    "CVE-2024-30071",
    "CVE-2024-30079",
    "CVE-2024-30081",
    "CVE-2024-30098",
    "CVE-2024-35270",
    "CVE-2024-37969",
    "CVE-2024-37970",
    "CVE-2024-37971",
    "CVE-2024-37972",
    "CVE-2024-37973",
    "CVE-2024-37974",
    "CVE-2024-37975",
    "CVE-2024-37981",
    "CVE-2024-37984",
    "CVE-2024-37986",
    "CVE-2024-37987",
    "CVE-2024-37988",
    "CVE-2024-37989",
    "CVE-2024-38010",
    "CVE-2024-38011",
    "CVE-2024-38013",
    "CVE-2024-38017",
    "CVE-2024-38019",
    "CVE-2024-38022",
    "CVE-2024-38025",
    "CVE-2024-38027",
    "CVE-2024-38028",
    "CVE-2024-38030",
    "CVE-2024-38032",
    "CVE-2024-38033",
    "CVE-2024-38034",
    "CVE-2024-38041",
    "CVE-2024-38043",
    "CVE-2024-38047",
    "CVE-2024-38048",
    "CVE-2024-38049",
    "CVE-2024-38050",
    "CVE-2024-38051",
    "CVE-2024-38052",
    "CVE-2024-38053",
    "CVE-2024-38054",
    "CVE-2024-38055",
    "CVE-2024-38056",
    "CVE-2024-38057",
    "CVE-2024-38058",
    "CVE-2024-38059",
    "CVE-2024-38060",
    "CVE-2024-38061",
    "CVE-2024-38062",
    "CVE-2024-38064",
    "CVE-2024-38065",
    "CVE-2024-38066",
    "CVE-2024-38068",
    "CVE-2024-38069",
    "CVE-2024-38070",
    "CVE-2024-38079",
    "CVE-2024-38085",
    "CVE-2024-38091",
    "CVE-2024-38101",
    "CVE-2024-38102",
    "CVE-2024-38104",
    "CVE-2024-38105",
    "CVE-2024-38112",
    "CVE-2024-38517",
    "CVE-2024-39684"
  );
  script_xref(name:"MSKB", value:"5040427");
  script_xref(name:"MSFT", value:"MS24-5040427");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/07/30");
  script_xref(name:"IAVA", value:"2024-A-0408-S");
  script_xref(name:"IAVA", value:"2024-A-0407-S");

  script_name(english:"KB5040427: Windows 10 Version 21H2 / Windows 10 Version 22H2 Security Update (July 2024)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security update 5040427. It is, therefore, affected by multiple vulnerabilities

  - RADIUS Protocol under RFC 2865 is susceptible to forgery attacks by a local attacker who can modify any
    valid Response (Access-Accept, Access-Reject, or Access-Challenge) to any other response using a chosen-
    prefix collision attack against MD5 Response Authenticator signature. (CVE-2024-3596)
  
  - A remote code execution vulnerability. An attacker can exploit this to bypass authentication and execute 
    unauthorized arbitrary commands. (CVE-2024-30013, CVE-2024-38104)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/help/5040427");
  script_set_attribute(attribute:"solution", value:
"Apply Security Update 5040427");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-30013");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-3596");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/09");

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

bulletin = 'MS24-07';
kbs = make_list(
  '5040427'
);

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit('SMB/Registry/Enumerated');
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp_range(win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

var os_name = get_kb_item("SMB/ProductName");

if ( (("enterprise" >< tolower(os_name) && "ltsc" >< tolower(os_name))
  && 
  smb_check_rollup(os:'10',
                   os_build:19044,
                   rollup_date:'07_2024',
                   bulletin:bulletin,
                   rollup_kb_list:[5040427])
)
||
  smb_check_rollup(os:'10',
                   os_build:19045,
                   rollup_date:'07_2024',
                   bulletin:bulletin,
                   rollup_kb_list:[5040427])
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
