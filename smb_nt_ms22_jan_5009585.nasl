#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156623);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/17");

  script_cve_id(
    "CVE-2022-21833",
    "CVE-2022-21834",
    "CVE-2022-21835",
    "CVE-2022-21836",
    "CVE-2022-21838",
    "CVE-2022-21843",
    "CVE-2022-21848",
    "CVE-2022-21849",
    "CVE-2022-21850",
    "CVE-2022-21851",
    "CVE-2022-21857",
    "CVE-2022-21859",
    "CVE-2022-21860",
    "CVE-2022-21862",
    "CVE-2022-21864",
    "CVE-2022-21866",
    "CVE-2022-21867",
    "CVE-2022-21868",
    "CVE-2022-21870",
    "CVE-2022-21871",
    "CVE-2022-21873",
    "CVE-2022-21874",
    "CVE-2022-21875",
    "CVE-2022-21876",
    "CVE-2022-21878",
    "CVE-2022-21880",
    "CVE-2022-21881",
    "CVE-2022-21883",
    "CVE-2022-21885",
    "CVE-2022-21889",
    "CVE-2022-21890",
    "CVE-2022-21892",
    "CVE-2022-21893",
    "CVE-2022-21894",
    "CVE-2022-21895",
    "CVE-2022-21897",
    "CVE-2022-21899",
    "CVE-2022-21900",
    "CVE-2022-21901",
    "CVE-2022-21903",
    "CVE-2022-21904",
    "CVE-2022-21905",
    "CVE-2022-21908",
    "CVE-2022-21911",
    "CVE-2022-21913",
    "CVE-2022-21914",
    "CVE-2022-21915",
    "CVE-2022-21916",
    "CVE-2022-21919",
    "CVE-2022-21920",
    "CVE-2022-21922",
    "CVE-2022-21924",
    "CVE-2022-21925",
    "CVE-2022-21928",
    "CVE-2022-21958",
    "CVE-2022-21959",
    "CVE-2022-21960",
    "CVE-2022-21961",
    "CVE-2022-21962",
    "CVE-2022-21963"
  );
  script_xref(name:"MSKB", value:"5009585");
  script_xref(name:"MSFT", value:"MS22-5009585");
  script_xref(name:"IAVA", value:"2022-A-0012-S");
  script_xref(name:"IAVA", value:"2022-A-0016-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/16");

  script_name(english:"KB5009585:  Windows 10 LTS 1507 Security Updates (January 2022)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security update 5009585. It is, therefore, affected by multiple vulnerabilities:

  - A remote code execution vulnerability. An attacker can exploit this to bypass authentication and execute 
    unauthorized arbitrary commands. 
    (CVE-2022-21962, CVE-2022-21959, CVE-2022-21963,
    CVE-2022-21960, CVE-2022-21928, CVE-2022-21874,
    CVE-2022-21961, CVE-2022-21958, CVE-2022-21893,
    CVE-2022-21892, CVE-2022-21878, CVE-2022-21851,
    CVE-2022-21850, CVE-2022-21849, CVE-2022-21922)
    
  - An elevation of privilege vulnerability. An attacker can exploit this to gain elevated privileges.
    (CVE-2022-21908, CVE-2022-21903, CVE-2022-21901,
     CVE-2022-21897, CVE-2022-21885, CVE-2022-21881,
     CVE-2022-21875, CVE-2022-21873, CVE-2022-21870,
     CVE-2022-21868, CVE-2022-21867, CVE-2022-21866,
     CVE-2022-21864, CVE-2022-21862, CVE-2022-21860,
     CVE-2022-21859, CVE-2022-21857, CVE-2022-21838,
     CVE-2022-21835, CVE-2022-21834, CVE-2022-21833,
     CVE-2022-21914, CVE-2022-21895, CVE-2022-21916,
     CVE-2022-21919, CVE-2022-21871, CVE-2022-21920)

  - A denial of service (DoS) vulnerability. An attacker can exploit this issue to cause the affected component to deny system or application services.
    (CVE-2022-21911, CVE-2022-21889, CVE-2022-21890, 
      CVE-2022-21883, CVE-2022-21843, CVE-2022-21848)");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5009585");
  script_set_attribute(attribute:"solution", value:
"Apply Security Update 5009585");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-21874");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows_10_1507");
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

bulletin = 'MS22-01';
kbs = make_list(
  '5009585'
);

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit('SMB/Registry/Enumerated');
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp_range(win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  smb_check_rollup(os:'10',
                   os_build:'10240',
                   rollup_date:'01_2022',
                   bulletin:bulletin,
                   rollup_kb_list:[5009585])
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
