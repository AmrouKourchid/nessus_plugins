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
  script_id(123940);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/17");

  script_cve_id(
    "CVE-2019-0688",
    "CVE-2019-0730",
    "CVE-2019-0731",
    "CVE-2019-0732",
    "CVE-2019-0735",
    "CVE-2019-0752",
    "CVE-2019-0753",
    "CVE-2019-0764",
    "CVE-2019-0790",
    "CVE-2019-0791",
    "CVE-2019-0792",
    "CVE-2019-0793",
    "CVE-2019-0794",
    "CVE-2019-0795",
    "CVE-2019-0796",
    "CVE-2019-0802",
    "CVE-2019-0803",
    "CVE-2019-0805",
    "CVE-2019-0835",
    "CVE-2019-0836",
    "CVE-2019-0838",
    "CVE-2019-0839",
    "CVE-2019-0842",
    "CVE-2019-0844",
    "CVE-2019-0845",
    "CVE-2019-0846",
    "CVE-2019-0847",
    "CVE-2019-0848",
    "CVE-2019-0849",
    "CVE-2019-0851",
    "CVE-2019-0853",
    "CVE-2019-0856",
    "CVE-2019-0859",
    "CVE-2019-0862",
    "CVE-2019-0877",
    "CVE-2019-0879"
  );
  script_xref(name:"MSKB", value:"4493446");
  script_xref(name:"MSKB", value:"4493467");
  script_xref(name:"MSFT", value:"MS19-4493446");
  script_xref(name:"MSFT", value:"MS19-4493467");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/08/15");
  script_xref(name:"CEA-ID", value:"CEA-2020-0129");

  script_name(english:"KB4493467: Windows 8.1 and Windows Server 2012 R2 April 2019 Security Update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security update 4493467
or cumulative update 4493446. It is, therefore, affected by
multiple vulnerabilities :

  - A security feature bypass vulnerability exists in
    Windows which could allow an attacker to bypass Device
    Guard when Windows improperly handles calls to the LUAFV
    driver (luafv.sys). An attacker who successfully
    exploited this vulnerability could circumvent a User
    Mode Code Integrity (UMCI) policy on the machine.
    (CVE-2019-0732)

  - An information disclosure vulnerability exists when the
    Terminal Services component improperly discloses the
    contents of its memory. An attacker who successfully
    exploited the vulnerability could obtain information to
    further compromise a users system.  (CVE-2019-0839)

  - A remote code execution vulnerability exists in the way
    that the VBScript engine handles objects in memory. The
    vulnerability could corrupt memory in such a way that an
    attacker could execute arbitrary code in the context of
    the current user. An attacker who successfully exploited
    the vulnerability could gain the same user rights as the
    current user.  (CVE-2019-0842)

  - A remote code execution vulnerability exists when
    Windows improperly handles objects in memory. An
    attacker who successfully exploited these
    vulnerabilities could take control of an affected
    system.  (CVE-2019-0856)

  - An information disclosure vulnerability exists when the
    Windows TCP/IP stack improperly handles fragmented IP
    packets. An attacker who successfully exploited this
    vulnerability could obtain information to further
    compromise the users system.  (CVE-2019-0688)

  - A remote code execution vulnerability exists when the
    Microsoft XML Core Services MSXML parser processes user
    input. An attacker who successfully exploited the
    vulnerability could run malicious code remotely to take
    control of the users system.  (CVE-2019-0790,
    CVE-2019-0791, CVE-2019-0792, CVE-2019-0793,
    CVE-2019-0795)

  - An elevation of privilege vulnerability exists in
    Windows when the Win32k component fails to properly
    handle objects in memory. An attacker who successfully
    exploited this vulnerability could run arbitrary code in
    kernel mode. An attacker could then install programs;
    view, change, or delete data; or create new accounts
    with full user rights.  (CVE-2019-0803, CVE-2019-0859)

  - A remote code execution vulnerability exists in the way
    that the scripting engine handles objects in memory in
    Internet Explorer. The vulnerability could corrupt
    memory in such a way that an attacker could execute
    arbitrary code in the context of the current user. An
    attacker who successfully exploited the vulnerability
    could gain the same user rights as the current user.
    (CVE-2019-0752, CVE-2019-0753, CVE-2019-0862)

  - A remote code execution vulnerability exists when the
    Windows Jet Database Engine improperly handles objects
    in memory. An attacker who successfully exploited this
    vulnerability could execute arbitrary code on a victim
    system. An attacker could exploit this vulnerability by
    enticing a victim to open a specially crafted file. The
    update addresses the vulnerability by correcting the way
    the Windows Jet Database Engine handles objects in
    memory. (CVE-2019-0846, CVE-2019-0847, CVE-2019-0851,
    CVE-2019-0877, CVE-2019-0879)

  - An elevation of privilege vulnerability exists when
    Windows improperly handles calls to the LUAFV driver
    (luafv.sys). An attacker who successfully exploited this
    vulnerability could run arbitrary code in the security
    context of the local system. An attacker could then
    install programs; view, change, or delete data; or
    create new accounts with full user rights.
    (CVE-2019-0730, CVE-2019-0731, CVE-2019-0805,
    CVE-2019-0836)

  - An information disclosure vulnerability exists when the
    Windows GDI component improperly discloses the contents
    of its memory. An attacker who successfully exploited
    the vulnerability could obtain information to further
    compromise the users system. There are multiple ways an
    attacker could exploit the vulnerability, such as by
    convincing a user to open a specially crafted document,
    or by convincing a user to visit an untrusted webpage.
    The security update addresses the vulnerability by
    correcting how the Windows GDI component handles objects
    in memory. (CVE-2019-0802, CVE-2019-0849)

  - An information disclosure vulnerability exists when
    Windows Task Scheduler improperly discloses credentials
    to Windows Credential Manager. An attacker who
    successfully exploited the vulnerability could obtain
    information to further compromise the users system. An
    attacker could then install programs; view, change, or
    delete data; or create new accounts with full user
    rights.  (CVE-2019-0838)

  - An information disclosure vulnerability exists when the
    scripting engine does not properly handle objects in
    memory. An attacker who successfully exploited the
    vulnerability could obtain information to further
    compromise the users system.  (CVE-2019-0835)

  - An elevation of privilege vulnerability exists when
    Windows improperly handles calls to the LUAFV driver
    (luafv.sys). An attacker who successfully exploited this
    vulnerability could set the short name of a file with a
    long name to an arbitrary short name, overriding the
    file system with limited privileges.  (CVE-2019-0796)

  - An information disclosure vulnerability exists when the
    win32k component improperly provides kernel information.
    An attacker who successfully exploited the vulnerability
    could obtain information to further compromise the users
    system.  (CVE-2019-0848)

  - An information disclosure vulnerability exists when the
    Windows kernel improperly handles objects in memory. An
    attacker who successfully exploited this vulnerability
    could obtain information to further compromise the users
    system.  (CVE-2019-0844)

  - An elevation of privilege vulnerability exists when the
    Windows Client Server Run-Time Subsystem (CSRSS) fails
    to properly handle objects in memory. An attacker who
    successfully exploited this vulnerability could run
    arbitrary code. An attacker could then install programs;
    view, change, or delete data; or create new accounts
    with full user rights.  (CVE-2019-0735)

  - A remote code execution vulnerability exists when OLE
    automation improperly handles objects in memory. An
    attacker who successfully exploited the vulnerability
    could gain execution on the victim system.
    (CVE-2019-0794)

  - A remote code execution vulnerability exists when the
    IOleCvt interface renders ASP webpage content. An
    attacker who successfully exploited the vulnerability
    could run malicious code remotely to take control of the
    users system.  (CVE-2019-0845)

  - A tampering vulnerability exists when Microsoft browsers
    do not properly validate input under specific
    conditions. An attacker who exploited the vulnerability
    could pass custom command line parameters.
    (CVE-2019-0764)

  - A remote code execution vulnerability exists in the way
    that the Windows Graphics Device Interface (GDI) handles
    objects in the memory. An attacker who successfully
    exploited this vulnerability could take control of the
    affected system. An attacker could then install
    programs; view, change, or delete data; or create new
    accounts with full user rights.  (CVE-2019-0853)");
  # https://support.microsoft.com/en-us/help/4493446/windows-8-1-update-kb4493446
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?60dedb61");
  # https://support.microsoft.com/en-us/help/4493467/windows-8-1-update-kb4493467
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4c9ecc3f");
  script_set_attribute(attribute:"solution", value:
"Apply Security Only update KB4493467 or Cumulative Update KB4493446.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0853");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows_8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows_server_2012:r2");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_check_rollup.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = "MS19-04";
kbs = make_list('4493467', '4493446');

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
                   rollup_date:"04_2019",
                   bulletin:bulletin,
                   rollup_kb_list:[4493467, 4493446])
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
