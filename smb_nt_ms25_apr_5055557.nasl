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
  script_id(234049);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/11");

  script_cve_id(
    "CVE-2025-21174",
    "CVE-2025-21191",
    "CVE-2025-21197",
    "CVE-2025-21203",
    "CVE-2025-21204",
    "CVE-2025-21205",
    "CVE-2025-21221",
    "CVE-2025-21222",
    "CVE-2025-26637",
    "CVE-2025-26641",
    "CVE-2025-26647",
    "CVE-2025-26648",
    "CVE-2025-26652",
    "CVE-2025-26663",
    "CVE-2025-26664",
    "CVE-2025-26665",
    "CVE-2025-26667",
    "CVE-2025-26668",
    "CVE-2025-26669",
    "CVE-2025-26670",
    "CVE-2025-26671",
    "CVE-2025-26672",
    "CVE-2025-26673",
    "CVE-2025-26676",
    "CVE-2025-26679",
    "CVE-2025-26680",
    "CVE-2025-26686",
    "CVE-2025-26687",
    "CVE-2025-26688",
    "CVE-2025-27469",
    "CVE-2025-27470",
    "CVE-2025-27471",
    "CVE-2025-27472",
    "CVE-2025-27473",
    "CVE-2025-27474",
    "CVE-2025-27477",
    "CVE-2025-27478",
    "CVE-2025-27479",
    "CVE-2025-27480",
    "CVE-2025-27481",
    "CVE-2025-27483",
    "CVE-2025-27484",
    "CVE-2025-27485",
    "CVE-2025-27486",
    "CVE-2025-27487",
    "CVE-2025-27727",
    "CVE-2025-27732",
    "CVE-2025-27733",
    "CVE-2025-27737",
    "CVE-2025-27738",
    "CVE-2025-27740",
    "CVE-2025-27741",
    "CVE-2025-27742",
    "CVE-2025-29810",
    "CVE-2025-29824"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2025/04/29");
  script_xref(name:"MSKB", value:"5055557");
  script_xref(name:"MSFT", value:"MS25-5055557");
  script_xref(name:"IAVA", value:"2025-A-0255");
  script_xref(name:"IAVA", value:"2025-A-0256");

  script_name(english:"KB5055557: Windows Server 2012 R2 Security Update (April 2025)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security update 5055557. It is, therefore, affected by multiple vulnerabilities

  - Use after free in Windows Win32K - GRFX allows an unauthorized attacker to elevate privileges over a
    network. (CVE-2025-26687)

  - A remote code execution vulnerability. An attacker can exploit this to bypass authentication and execute 
    unauthorized arbitrary commands. (CVE-2025-27481)
  
  - An elevation of privilege vulnerability. An attacker can exploit this to gain elevated privileges. (CVE-2025-27740)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/help/5055557");
  script_set_attribute(attribute:"solution", value:
"Apply Security Update 5055557");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-27481");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2025-27740");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/04/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows_server_2012:r2");
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

var bulletin = 'MS25-04';
var kbs = make_list(
  '5055557'
);

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit('SMB/Registry/Enumerated');
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp_range(win81:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

var share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  smb_check_rollup(os:'6.3',
                   sp:0,
                   rollup_date:'04_2025',
                   bulletin:bulletin,
                   rollup_kb_list:[5055557])
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
