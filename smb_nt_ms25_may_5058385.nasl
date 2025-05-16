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
  script_id(235856);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/13");

  script_cve_id(
    "CVE-2025-24063",
    "CVE-2025-26677",
    "CVE-2025-27468",
    "CVE-2025-29829",
    "CVE-2025-29830",
    "CVE-2025-29831",
    "CVE-2025-29832",
    "CVE-2025-29833",
    "CVE-2025-29835",
    "CVE-2025-29836",
    "CVE-2025-29837",
    "CVE-2025-29839",
    "CVE-2025-29840",
    "CVE-2025-29841",
    "CVE-2025-29842",
    "CVE-2025-29954",
    "CVE-2025-29956",
    "CVE-2025-29957",
    "CVE-2025-29958",
    "CVE-2025-29959",
    "CVE-2025-29960",
    "CVE-2025-29961",
    "CVE-2025-29962",
    "CVE-2025-29963",
    "CVE-2025-29964",
    "CVE-2025-29966",
    "CVE-2025-29967",
    "CVE-2025-29968",
    "CVE-2025-29969",
    "CVE-2025-29974",
    "CVE-2025-30385",
    "CVE-2025-30388",
    "CVE-2025-30394",
    "CVE-2025-30397",
    "CVE-2025-30400",
    "CVE-2025-32701",
    "CVE-2025-32706",
    "CVE-2025-32709"
  );
  script_xref(name:"MSKB", value:"5058385");
  script_xref(name:"MSKB", value:"5058500");
  script_xref(name:"MSFT", value:"MS25-5058385");
  script_xref(name:"MSFT", value:"MS25-5058500");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2025/06/03");

  script_name(english:"KB5058385: Windows Server 2022 / Azure Stack HCI 22H2 Security Update (May 2025)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security update 5058385 or Hot Patch 5058500. It is, therefore, affected by
 multiple vulnerabilities

  - Heap-based buffer overflow in Remote Desktop Gateway Service allows an unauthorized attacker to execute
    code over a network. (CVE-2025-29967)

  - Use of uninitialized resource in Windows Routing and Remote Access Service (RRAS) allows an unauthorized
    attacker to disclose information over a network. (CVE-2025-29830, CVE-2025-29958, CVE-2025-29959)

  - Out-of-bounds read in Windows Routing and Remote Access Service (RRAS) allows an unauthorized attacker to
    disclose information over a network. (CVE-2025-29832, CVE-2025-29835, CVE-2025-29836, CVE-2025-29960,
    CVE-2025-29961)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/help/5058385");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/help/5058500");
  script_set_attribute(attribute:"solution", value:
"Apply Security Update 5058385 or Hot Patch 5058500");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-29967");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/05/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/05/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/05/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:azure_stack_hci:22h2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows_server_2022");
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

var bulletin = 'MS25-05';
var kbs = make_list(
  '5058385'
);

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit('SMB/Registry/Enumerated');
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp_range(win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

var share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

var wmi_patch_found = get_kb_item("WMI/Installed/Hotfix/KB5058500");

if (
  smb_check_rollup(os:'10',
                   os_build:20348,
                   rollup_date:'05_2025',
                   bulletin:bulletin,
                   rollup_kb_list:[5058385,5058500])
)
{
    # create vuln alert only if we havent seen the patch, exit no matter what.
  if (!wmi_patch_found) 
  {
    replace_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
    hotfix_security_hole();
  }
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, hotfix_get_audit_report());
}
