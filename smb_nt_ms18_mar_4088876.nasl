#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
#

include('compat.inc');

if (description)
{
  script_id(108291);
  script_version("1.24");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/08");

  script_cve_id(
    "CVE-2018-0811",
    "CVE-2018-0813",
    "CVE-2018-0814",
    "CVE-2018-0816",
    "CVE-2018-0817",
    "CVE-2018-0868",
    "CVE-2018-0878",
    "CVE-2018-0881",
    "CVE-2018-0883",
    "CVE-2018-0885",
    "CVE-2018-0886",
    "CVE-2018-0888",
    "CVE-2018-0889",
    "CVE-2018-0891",
    "CVE-2018-0894",
    "CVE-2018-0895",
    "CVE-2018-0896",
    "CVE-2018-0897",
    "CVE-2018-0898",
    "CVE-2018-0899",
    "CVE-2018-0900",
    "CVE-2018-0901",
    "CVE-2018-0904",
    "CVE-2018-0927",
    "CVE-2018-0929",
    "CVE-2018-0932",
    "CVE-2018-0935",
    "CVE-2018-0942",
    "CVE-2017-5715",
    "CVE-2017-5753",
    "CVE-2017-5754"
  );
  script_bugtraq_id(
    103230,
    103231,
    103232,
    103236,
    103238,
    103240,
    103241,
    103242,
    103243,
    103244,
    103245,
    103246,
    103248,
    103249,
    103250,
    103251,
    103256,
    103259,
    103261,
    103262,
    103265,
    103295,
    103298,
    103299,
    103307,
    103309,
    103310,
    103312
  );
  script_xref(name:"MSKB", value:"4088876");
  script_xref(name:"IAVA", value:"2018-A-0019");
  script_xref(name:"IAVA", value:"2018-A-0020");
  script_xref(name:"MSKB", value:"4088879");
  script_xref(name:"MSFT", value:"MS18-4088876");
  script_xref(name:"MSFT", value:"MS18-4088879");

  script_name(english:"KB4088879: Windows 8.1 and Windows Server 2012 R2 March 2018 Security Update (Meltdown)(Spectre)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security update 4088879
or cumulative update 4088876. It is, therefore, affected by
multiple vulnerabilities :

  - An vulnerability exists within microprocessors utilizing
    speculative execution and indirect branch prediction,
    which may allow an attacker with local user access to
    disclose information via a side-channel analysis.
    (CVE-2017-5715, CVE-2017-5753, CVE-2017-5754)

  - An information disclosure vulnerability exists when
    Windows Remote Assistance incorrectly processes XML
    External Entities (XXE). An attacker who successfully
    exploited the vulnerability could obtain information to
    further compromise the users system.  (CVE-2018-0878)

  - An information disclosure vulnerability exists when
    Internet Explorer improperly handles objects in memory.
    An attacker who successfully exploited the vulnerability
    could obtain information to further compromise the users
    system.  (CVE-2018-0929)

  - A remote code execution vulnerability exists when
    Windows Shell does not properly validate file copy
    destinations. An attacker who successfully exploited the
    vulnerability could run arbitrary code in the context of
    the current user. If the current user is logged on with
    administrative user rights, an attacker could take
    control of the affected system. An attacker could then
    install programs; view, change, or delete data; or
    create new accounts with full user rights. Users whose
    accounts are configured to have fewer user rights on the
    system could be less impacted than users who operate
    with administrative user rights.  (CVE-2018-0883)

  - An elevation of privilege vulnerability exists in
    Windows when the Microsoft Video Control mishandles
    objects in memory. An attacker who successfully
    exploited this vulnerability could run arbitrary code in
    system mode. An attacker could then install programs;
    view, change, or delete data; or create new accounts
    with full user rights.  (CVE-2018-0881)

  - An information disclosure vulnerability exists when
    affected Microsoft browsers improperly handle objects in
    memory. An attacker who successfully exploited this
    vulnerability could obtain information to further
    compromise the users system.  (CVE-2018-0927,
    CVE-2018-0932)

  - A remote code execution vulnerability exists in the way
    that the scripting engine handles objects in memory in
    Internet Explorer. The vulnerability could corrupt
    memory in such a way that an attacker could execute
    arbitrary code in the context of the current user. An
    attacker who successfully exploited the vulnerability
    could gain the same user rights as the current user.
    (CVE-2018-0889, CVE-2018-0935)

  - An elevation of privilege vulnerability exists when
    Internet Explorer fails a check, allowing sandbox
    escape. An attacker who successfully exploited the
    vulnerability could use the sandbox escape to elevate
    privileges on an affected system. This vulnerability by
    itself does not allow arbitrary code execution; however,
    it could allow arbitrary code to be run if the attacker
    uses it in combination with another vulnerability (such
    as a remote code execution vulnerability or another
    elevation of privilege vulnerability) that is capable of
    leveraging the elevated privileges when code execution
    is attempted. The update addresses the vulnerability by
    correcting how Internet Explorer handles zone and
    integrity settings. (CVE-2018-0942)

  - An information disclosure vulnerability exists when the
    Windows kernel improperly initializes objects in memory.
    (CVE-2018-0811, CVE-2018-0813, CVE-2018-0814)

  - A denial of service vulnerability exists when Microsoft
    Hyper-V Network Switch on a host server fails to
    properly validate input from a privileged user on a
    guest operating system. An attacker who successfully
    exploited the vulnerability could cause the host server
    to crash.  (CVE-2018-0885)

  - A remote code execution vulnerability exists in the
    Credential Security Support Provider protocol (CredSSP).
    An attacker who successfully exploited this
    vulnerability could relay user credentials and use them
    to execute code on the target system. CredSSP is an
    authentication provider which processes authentication
    requests for other applications; any application which
    depends on CredSSP for authentication may be vulnerable
    to this type of attack. As an example of how an attacker
    would exploit this vulnerability against Remote Desktop
    Protocol, the attacker would need to run a specially
    crafted application and perform a man-in-the-middle
    attack against a Remote Desktop Protocol session. An
    attacker could then install programs; view, change, or
    delete data; or create new accounts with full user
    rights. The security update addresses the vulnerability
    by correcting how Credential Security Support Provider
    protocol (CredSSP) validates requests during the
    authentication process. To be fully protected against
    this vulnerability users must enable Group Policy
    settings on their systems and update their Remote
    Desktop clients. The Group Policy settings are disabled
    by default to prevent connectivity problems and users
    must follow the instructions documented HERE to be fully
    protected. (CVE-2018-0886)

  - An information disclosure vulnerability exists in the
    Windows kernel that could allow an attacker to retrieve
    information that could lead to a Kernel Address Space
    Layout Randomization (ASLR) bypass. An attacker who
    successfully exploited the vulnerability could retrieve
    the memory address of a kernel object.  (CVE-2018-0894,
    CVE-2018-0895, CVE-2018-0896, CVE-2018-0897,
    CVE-2018-0898, CVE-2018-0899, CVE-2018-0900,
    CVE-2018-0901, CVE-2018-0904)

  - An elevation of privilege vulnerability exists in the
    Windows Installer when the Windows Installer fails to
    properly sanitize input leading to an insecure library
    loading behavior. A locally authenticated attacker could
    run arbitrary code with elevated system privileges. An
    attacker could then install programs; view, change, or
    delete data; or create new accounts with full user
    rights. The security update addresses the vulnerability
    by correcting the input sanitization error to preclude
    unintended elevation. (CVE-2018-0868)

  - An elevation of privilege vulnerability exists in the
    way that the Windows Graphics Device Interface (GDI)
    handles objects in memory. An attacker who successfully
    exploited this vulnerability could run arbitrary code in
    kernel mode. An attacker could then install programs;
    view, change, or delete data; or create new accounts
    with full user rights.  (CVE-2018-0816, CVE-2018-0817)

  - An information disclosure vulnerability exists when
    Windows Hyper-V on a host operating system fails to
    properly validate input from an authenticated user on a
    guest operating system.  (CVE-2018-0888)

  - An information disclosure vulnerability exists when the
    scripting engine does not properly handle objects in
    memory in Microsoft browsers. An attacker who
    successfully exploited the vulnerability could obtain
    information to further compromise the users system.
    (CVE-2018-0891)");
  # https://support.microsoft.com/en-us/help/4088876/windows-81-update-kb4088876
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2ace7125");
  # https://support.microsoft.com/en-us/help/4088879/windows-81-update-kb4088879
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?99648598");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/ADV180002
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?573cb1ef");
  # https://support.microsoft.com/en-us/help/4072698/windows-server-speculative-execution-side-channel-vulnerabilities-prot
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8902cebb");
  script_set_attribute(attribute:"solution", value:
"Apply Security Only update KB4088879 or Cumulative Update KB4088876
as well as refer to the KB article for additional information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0935");
  script_set_attribute(attribute:"cvss3_score_rationale", value:"Scoring adjustsed to align with CVSS 3.1 attack complexity guidance.");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows_8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows_server_2012:r2");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2018-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_check_rollup.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl", "smb_enum_services.nasl", "microsoft_windows_env_vars.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("misc_func.inc");
include("smb_reg_query.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = "MS18-03";
kbs = make_list('4088876', '4088879');

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win81:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

# Windows 8 EOL
productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ("Windows 8" >< productname && "8.1" >!< productname)
  audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);

if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  smb_check_rollup(os:"6.3",
                   sp:0,
                   rollup_date:"03_2018_2",
                   bulletin:bulletin,
                   rollup_kb_list:[4088876, 4088879])
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
