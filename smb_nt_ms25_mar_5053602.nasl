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
  script_id(232613);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/18");

  script_cve_id(
    "CVE-2024-9157",
    "CVE-2025-21180",
    "CVE-2025-21247",
    "CVE-2025-24035",
    "CVE-2025-24044",
    "CVE-2025-24046",
    "CVE-2025-24048",
    "CVE-2025-24050",
    "CVE-2025-24051",
    "CVE-2025-24054",
    "CVE-2025-24055",
    "CVE-2025-24056",
    "CVE-2025-24059",
    "CVE-2025-24061",
    "CVE-2025-24066",
    "CVE-2025-24067",
    "CVE-2025-24071",
    "CVE-2025-24072",
    "CVE-2025-24076",
    "CVE-2025-24084",
    "CVE-2025-24984",
    "CVE-2025-24985",
    "CVE-2025-24987",
    "CVE-2025-24988",
    "CVE-2025-24991",
    "CVE-2025-24992",
    "CVE-2025-24993",
    "CVE-2025-24994",
    "CVE-2025-24995",
    "CVE-2025-24996",
    "CVE-2025-24997",
    "CVE-2025-26633",
    "CVE-2025-26645"
  );
  script_xref(name:"MSKB", value:"5053602");
  script_xref(name:"MSFT", value:"MS25-5053602");
  script_xref(name:"IAVA", value:"2025-A-0181-S");
  script_xref(name:"IAVA", value:"2025-A-0182-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2025/05/08");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2025/04/01");

  script_name(english:"KB5053602: Windows 11 version 22H2 /  Windows 11 version 23H2 Security Update (March 2025)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security update 5053602. It is, therefore, affected by multiple vulnerabilities

  - Relative path traversal in Remote Desktop Client allows an unauthorized attacker to execute code over a
    network. (CVE-2025-26645)

  - Sensitive data storage in improperly locked memory in Windows Remote Desktop Services allows an
    unauthorized attacker to execute code over a network. (CVE-2025-24035)

  - ** UNSUPPORTED WHEN ASSIGNED ** A privilege escalation vulnerability in CxUIUSvc64.exe and CxUIUSvc32.exe
    of Synaptics audio drivers allows a local authorized attacker to load a DLL in a privileged process. Out
    of an abundance of caution, this CVE ID is being assigned to better serve our customers and ensure all who
    are still running this product understand that the product is End-of-Life and should be removed. For more
    information on this, refer to the CVE Record's reference information. (CVE-2024-9157)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/help/5053602");
  script_set_attribute(attribute:"solution", value:
"Apply Security Update 5053602");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-26645");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/03/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/03/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows_11_22h2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows_11_23h2");
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

var bulletin = 'MS25-03';
var kbs = make_list(
  '5053602'
);

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit('SMB/Registry/Enumerated');
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp_range(win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

var share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

var os_name = get_kb_item("SMB/ProductName");

if (  ( ("enterprise" >< tolower(os_name) || "education" >< tolower(os_name))
  &&
  smb_check_rollup(os:'10',
                   os_build:22621,
                   rollup_date:'03_2025',
                   bulletin:bulletin,
                   rollup_kb_list:[5053602])
  )
|| 
  smb_check_rollup(os:'10',
                   os_build:22631,
                   rollup_date:'03_2025',
                   bulletin:bulletin,
                   rollup_kb_list:[5053602])
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
