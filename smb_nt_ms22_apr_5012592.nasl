#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159671);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/28");

  script_cve_id(
    "CVE-2022-21983",
    "CVE-2022-22008",
    "CVE-2022-22009",
    "CVE-2022-23257",
    "CVE-2022-23268",
    "CVE-2022-24474",
    "CVE-2022-24479",
    "CVE-2022-24481",
    "CVE-2022-24482",
    "CVE-2022-24483",
    "CVE-2022-24485",
    "CVE-2022-24486",
    "CVE-2022-24487",
    "CVE-2022-24488",
    "CVE-2022-24491",
    "CVE-2022-24492",
    "CVE-2022-24493",
    "CVE-2022-24494",
    "CVE-2022-24495",
    "CVE-2022-24496",
    "CVE-2022-24497",
    "CVE-2022-24498",
    "CVE-2022-24499",
    "CVE-2022-24500",
    "CVE-2022-24521",
    "CVE-2022-24527",
    "CVE-2022-24528",
    "CVE-2022-24530",
    "CVE-2022-24533",
    "CVE-2022-24534",
    "CVE-2022-24537",
    "CVE-2022-24540",
    "CVE-2022-24541",
    "CVE-2022-24542",
    "CVE-2022-24544",
    "CVE-2022-24545",
    "CVE-2022-24546",
    "CVE-2022-24547",
    "CVE-2022-24549",
    "CVE-2022-24550",
    "CVE-2022-26786",
    "CVE-2022-26787",
    "CVE-2022-26788",
    "CVE-2022-26789",
    "CVE-2022-26790",
    "CVE-2022-26792",
    "CVE-2022-26793",
    "CVE-2022-26794",
    "CVE-2022-26795",
    "CVE-2022-26796",
    "CVE-2022-26797",
    "CVE-2022-26798",
    "CVE-2022-26801",
    "CVE-2022-26802",
    "CVE-2022-26803",
    "CVE-2022-26807",
    "CVE-2022-26808",
    "CVE-2022-26809",
    "CVE-2022-26826",
    "CVE-2022-26830",
    "CVE-2022-26831",
    "CVE-2022-26904",
    "CVE-2022-26914",
    "CVE-2022-26915",
    "CVE-2022-26916",
    "CVE-2022-26917",
    "CVE-2022-26918",
    "CVE-2022-26919",
    "CVE-2022-26920"
  );
  script_xref(name:"MSKB", value:"5012592");
  script_xref(name:"MSFT", value:"MS22-5012592");
  script_xref(name:"IAVA", value:"2022-A-0147-S");
  script_xref(name:"IAVA", value:"2022-A-0145-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/04");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/16");

  script_name(english:"KB5012592: Windows 11 Security Update (April 2022)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security update 5012592. It is, therefore, affected by multiple vulnerabilities:

  - A denial of service (DoS) vulnerability. An attacker can
    exploit this issue to cause the affected component to
    deny system or application services. (CVE-2022-26831
    CVE-2022-26915, CVE-2022-23268)
  
  - A remote code execution vulnerability. An attacker can
    exploit this to bypass authentication and execute
    unauthorized arbitrary commands. (CVE-2022-26916, 
    CVE-2022-26917, CVE-2022-26809, CVE-2022-26919, 
    CVE-2022-26830, CVE-2022-26918, CVE-2022-26826, 
    CVE-2022-24545, CVE-2022-24541, CVE-2022-24492,
    CVE-2022-24491, CVE-2022-24537, CVE-2022-24487,
    CVE-2022-24534, CVE-2022-24485, CVE-2022-24533,
    CVE-2022-24495, CVE-2022-24528, CVE-2022-23257,
    CVE-2022-21983, CVE-2022-22009, CVE-2022-22008, 
    CVE-2022-24500)

  - An information disclosure vulnerability. An attacker can
    exploit this to disclose potentially sensitive
    information. (CVE-2022-26920, CVE-2022-24493, 
    CVE-2022-24498, CVE-2022-24483)

  - An elevation of privilege vulnerability. An attacker can
    exploit this to gain elevated privileges. (CVE-2022-26789, 
    CVE-2022-26786, CVE-2022-26802, CVE-2022-26808, 
    CVE-2022-26807, CVE-2022-26795, CVE-2022-26792, 
    CVE-2022-26794, CVE-2022-26904, CVE-2022-26803, 
    CVE-2022-26797, CVE-2022-26787, CVE-2022-24549, 
    CVE-2022-26914, CVE-2022-26801, CVE-2022-26798, 
    CVE-2022-26793, CVE-2022-26796, CVE-2022-26790, 
    CVE-2022-26788, CVE-2022-24496, CVE-2022-24544, 
    CVE-2022-24540, CVE-2022-24488, CVE-2022-24486, 
    CVE-2022-24481, CVE-2022-24479, CVE-2022-24527, 
    CVE-2022-24474, CVE-2022-24521, CVE-2022-24550, 
    CVE-2022-24499, CVE-2022-24547, CVE-2022-24546, 
    CVE-2022-24494, CVE-2022-24542, CVE-2022-24530)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5012592");
  script_set_attribute(attribute:"solution", value:
"Apply Security Update 5012592");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-26809");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'User Profile Arbitrary Junction Creation Local Privilege Elevation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows_11_21h2");
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

bulletin = 'MS22-04';
kbs = make_list(
  '5012592'
);

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit('SMB/Registry/Enumerated');
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp_range(win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  smb_check_rollup(os:'10',
                   sp:0,
                   os_build:'22000',
                   rollup_date:'04_2022',
                   bulletin:bulletin,
                   rollup_kb_list:[5012592])
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
