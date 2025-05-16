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
  script_id(214111);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/18");

  script_cve_id(
    "CVE-2024-7344",
    "CVE-2025-21189",
    "CVE-2025-21210",
    "CVE-2025-21211",
    "CVE-2025-21213",
    "CVE-2025-21214",
    "CVE-2025-21215",
    "CVE-2025-21217",
    "CVE-2025-21218",
    "CVE-2025-21220",
    "CVE-2025-21223",
    "CVE-2025-21226",
    "CVE-2025-21227",
    "CVE-2025-21228",
    "CVE-2025-21229",
    "CVE-2025-21230",
    "CVE-2025-21231",
    "CVE-2025-21232",
    "CVE-2025-21233",
    "CVE-2025-21236",
    "CVE-2025-21237",
    "CVE-2025-21238",
    "CVE-2025-21240",
    "CVE-2025-21242",
    "CVE-2025-21243",
    "CVE-2025-21244",
    "CVE-2025-21245",
    "CVE-2025-21246",
    "CVE-2025-21249",
    "CVE-2025-21250",
    "CVE-2025-21251",
    "CVE-2025-21252",
    "CVE-2025-21255",
    "CVE-2025-21256",
    "CVE-2025-21258",
    "CVE-2025-21260",
    "CVE-2025-21261",
    "CVE-2025-21263",
    "CVE-2025-21265",
    "CVE-2025-21266",
    "CVE-2025-21268",
    "CVE-2025-21269",
    "CVE-2025-21270",
    "CVE-2025-21272",
    "CVE-2025-21273",
    "CVE-2025-21276",
    "CVE-2025-21277",
    "CVE-2025-21278",
    "CVE-2025-21281",
    "CVE-2025-21282",
    "CVE-2025-21285",
    "CVE-2025-21286",
    "CVE-2025-21287",
    "CVE-2025-21288",
    "CVE-2025-21289",
    "CVE-2025-21290",
    "CVE-2025-21293",
    "CVE-2025-21294",
    "CVE-2025-21295",
    "CVE-2025-21296",
    "CVE-2025-21297",
    "CVE-2025-21298",
    "CVE-2025-21300",
    "CVE-2025-21302",
    "CVE-2025-21303",
    "CVE-2025-21305",
    "CVE-2025-21306",
    "CVE-2025-21307",
    "CVE-2025-21308",
    "CVE-2025-21309",
    "CVE-2025-21310",
    "CVE-2025-21312",
    "CVE-2025-21318",
    "CVE-2025-21319",
    "CVE-2025-21320",
    "CVE-2025-21321",
    "CVE-2025-21324",
    "CVE-2025-21327",
    "CVE-2025-21328",
    "CVE-2025-21329",
    "CVE-2025-21331",
    "CVE-2025-21332",
    "CVE-2025-21336",
    "CVE-2025-21338",
    "CVE-2025-21339",
    "CVE-2025-21341",
    "CVE-2025-21374",
    "CVE-2025-21378",
    "CVE-2025-21389",
    "CVE-2025-21409",
    "CVE-2025-21411",
    "CVE-2025-21413",
    "CVE-2025-21417"
  );
  script_xref(name:"MSKB", value:"5050004");
  script_xref(name:"MSFT", value:"MS25-5050004");
  script_xref(name:"IAVA", value:"2025-A-0034-S");
  script_xref(name:"IAVA", value:"2025-A-0033-S");

  script_name(english:"KB5050004: Windows Server 2012 Security Update (January 2025)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security update 5050004. It is, therefore, affected by multiple vulnerabilities

  - Windows Reliable Multicast Transport Driver (RMCAST) Remote Code Execution Vulnerability (CVE-2025-21307)

  - Windows Telephony Service Remote Code Execution Vulnerability (CVE-2025-21223, CVE-2025-21233,
    CVE-2025-21236, CVE-2025-21237, CVE-2025-21238, CVE-2025-21240, CVE-2025-21243, CVE-2025-21244,
    CVE-2025-21245, CVE-2025-21246, CVE-2025-21250, CVE-2025-21252, CVE-2025-21266, CVE-2025-21273,
    CVE-2025-21282, CVE-2025-21286, CVE-2025-21302, CVE-2025-21303, CVE-2025-21305, CVE-2025-21306,
    CVE-2025-21339, CVE-2025-21409, CVE-2025-21411, CVE-2025-21413, CVE-2025-21417)

  - Windows BitLocker Information Disclosure Vulnerability (CVE-2025-21210, CVE-2025-21214)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/help/5050004");
  script_set_attribute(attribute:"solution", value:
"Apply Security Update 5050004");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-21417");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Windows Escalate Service Permissions Local Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/01/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/01/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows_server_2012");
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

var bulletin = 'MS25-01';
var kbs = make_list(
  '5050004'
);

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit('SMB/Registry/Enumerated');
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp_range(win8:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

var share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  smb_check_rollup(os:'6.2',
                   sp:0,
                   rollup_date:'01_2025',
                   bulletin:bulletin,
                   rollup_kb_list:[5050004])
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
