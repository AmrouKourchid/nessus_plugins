##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
##

include('compat.inc');

if (description)
{
  script_id(146345);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/17");

  script_cve_id(
    "CVE-2021-1698",
    "CVE-2021-1722",
    "CVE-2021-1727",
    "CVE-2021-1731",
    "CVE-2021-1732",
    "CVE-2021-1734",
    "CVE-2021-24074",
    "CVE-2021-24075",
    "CVE-2021-24076",
    "CVE-2021-24077",
    "CVE-2021-24078",
    "CVE-2021-24079",
    "CVE-2021-24080",
    "CVE-2021-24081",
    "CVE-2021-24082",
    "CVE-2021-24083",
    "CVE-2021-24084",
    "CVE-2021-24086",
    "CVE-2021-24088",
    "CVE-2021-24091",
    "CVE-2021-24093",
    "CVE-2021-24094",
    "CVE-2021-24096",
    "CVE-2021-24098",
    "CVE-2021-24102",
    "CVE-2021-24103",
    "CVE-2021-24106",
    "CVE-2021-25195"
  );
  script_xref(name:"MSKB", value:"4601319");
  script_xref(name:"MSFT", value:"MS21-4601319");
  script_xref(name:"IAVA", value:"2021-A-0072-S");
  script_xref(name:"IAVA", value:"2021-A-0093-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/11/17");

  script_name(english:"KB4601319: Windows 10 version 2004 Feb 2021 Security Update");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security update 4601319.
It is, therefore, affected by multiple vulnerabilities :

  - An information disclosure vulnerability. An attacker can
    exploit this to disclose potentially sensitive
    information. (CVE-2021-1734, CVE-2021-24076,
    CVE-2021-24079, CVE-2021-24084, CVE-2021-24106)

  - A denial of service (DoS) vulnerability. An attacker can
    exploit this issue to cause the affected component to
    deny system or application services. (CVE-2021-24075,
    CVE-2021-24080, CVE-2021-24086, CVE-2021-24098)

  - A remote code execution vulnerability. An attacker can
    exploit this to bypass authentication and execute
    unauthorized arbitrary commands. (CVE-2021-1722,
    CVE-2021-24074, CVE-2021-24077, CVE-2021-24081,
    CVE-2021-24083, CVE-2021-24088, CVE-2021-24091,
    CVE-2021-24093, CVE-2021-24094)

  - An elevation of privilege vulnerability. An attacker can
    exploit this to gain elevated privileges.
    (CVE-2021-1698, CVE-2021-1727, CVE-2021-1732,
    CVE-2021-24096, CVE-2021-24102, CVE-2021-24103,
    CVE-2021-25195)

  - A security feature bypass vulnerability exists. An
    attacker can exploit this and bypass the security
    feature and perform unauthorized actions compromising
    the integrity of the system/application. (CVE-2021-1731,
    CVE-2021-24082)");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4601319");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released KB4601319 to address this issue.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-24094");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Win32k ConsoleControl Offset Confusion');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows_10_2004");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

bulletin = 'MS21-02';
kbs = make_list(
  '4601319'
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
                   os_build:'19041',
                   rollup_date:'02_2021',
                   bulletin:bulletin,
                   rollup_kb_list:[4601319])
|| 
smb_check_rollup(os:'10',
                   sp:0,
                   os_build:'19042',
                   rollup_date:'02_2021',
                   bulletin:bulletin,
                   rollup_kb_list:[4601319])
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
