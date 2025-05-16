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
  script_id(200343);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/17");

  script_cve_id(
    "CVE-2024-30063",
    "CVE-2024-30065",
    "CVE-2024-30066",
    "CVE-2024-30067",
    "CVE-2024-30068",
    "CVE-2024-30069",
    "CVE-2024-30076",
    "CVE-2024-30077",
    "CVE-2024-30078",
    "CVE-2024-30080",
    "CVE-2024-30082",
    "CVE-2024-30084",
    "CVE-2024-30085",
    "CVE-2024-30086",
    "CVE-2024-30087",
    "CVE-2024-30088",
    "CVE-2024-30089",
    "CVE-2024-30090",
    "CVE-2024-30091",
    "CVE-2024-30093",
    "CVE-2024-30094",
    "CVE-2024-30095",
    "CVE-2024-30096",
    "CVE-2024-30097",
    "CVE-2024-30099",
    "CVE-2024-35250",
    "CVE-2024-35265",
    "CVE-2024-38213"
  );
  script_xref(name:"MSKB", value:"5039211");
  script_xref(name:"MSFT", value:"MS24-5039211");
  script_xref(name:"IAVA", value:"2024-A-0343-S");
  script_xref(name:"IAVA", value:"2024-A-0345-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2025/01/06");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/11/05");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/09/03");

  script_name(english:"KB5039211: Windows 10 Version 21H2 / Windows 10 Version 22H2 Security Update (June 2024)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security update 5039211. It is, therefore, affected by multiple vulnerabilities

  - Microsoft Speech Application Programming Interface (SAPI) Remote Code Execution Vulnerability
    (CVE-2024-30097)

  - Windows Remote Access Connection Manager Information Disclosure Vulnerability (CVE-2024-30069)

  - Windows Container Manager Service Elevation of Privilege Vulnerability (CVE-2024-30076)

  - Microsoft Message Queuing (MSMQ) Remote Code Execution Vulnerability (CVE-2024-30080)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/help/5039211");
  script_set_attribute(attribute:"solution", value:
"Apply Security Update 5039211");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-30097");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-30080");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Windows Access Mode Mismatch LPE in ks.sys');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/06/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/06/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/11");

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

bulletin = 'MS24-06';
kbs = make_list(
  '5039211'
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
                   rollup_date:'06_2024',
                   bulletin:bulletin,
                   rollup_kb_list:[5039211])
)
||
  smb_check_rollup(os:'10',
                   os_build:19045,
                   rollup_date:'06_2024',
                   bulletin:bulletin,
                   rollup_kb_list:[5039211])
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
