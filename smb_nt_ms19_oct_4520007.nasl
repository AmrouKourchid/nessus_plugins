#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(129723);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/17");

  script_cve_id(
    "CVE-2019-0608",
    "CVE-2019-1060",
    "CVE-2019-1166",
    "CVE-2019-1238",
    "CVE-2019-1311",
    "CVE-2019-1315",
    "CVE-2019-1318",
    "CVE-2019-1319",
    "CVE-2019-1325",
    "CVE-2019-1326",
    "CVE-2019-1333",
    "CVE-2019-1339",
    "CVE-2019-1341",
    "CVE-2019-1342",
    "CVE-2019-1343",
    "CVE-2019-1344",
    "CVE-2019-1346",
    "CVE-2019-1357",
    "CVE-2019-1358",
    "CVE-2019-1359",
    "CVE-2019-1365",
    "CVE-2019-1371"
  );
  script_xref(name:"MSKB", value:"4520007");
  script_xref(name:"MSKB", value:"4519985");
  script_xref(name:"MSFT", value:"MS19-4520007");
  script_xref(name:"MSFT", value:"MS19-4519985");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/04/05");

  script_name(english:"KB4519985: Windows Server 2012 October 2019 Security Update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security update 4519985
or cumulative update 4520007. It is, therefore, affected by
multiple vulnerabilities :

  - A spoofing vulnerability exists when Microsoft Browsers
    improperly handle browser cookies. An attacker who
    successfully exploited this vulnerability could trick a
    browser into overwriting a secure cookie with an
    insecure cookie. The insecure cookie could serve as a
    pivot to chain an attack with other vulnerabilities in
    web services.  (CVE-2019-1357)

  - A remote code execution vulnerability exists when the
    Windows Jet Database Engine improperly handles objects
    in memory. An attacker who successfully exploited this
    vulnerability could execute arbitrary code on a victim
    system. An attacker could exploit this vulnerability by
    enticing a victim to open a specially crafted file. The
    update addresses the vulnerability by correcting the way
    the Windows Jet Database Engine handles objects in
    memory. (CVE-2019-1358, CVE-2019-1359)

  - A remote code execution vulnerability exists in the
    Windows Remote Desktop Client when a user connects to a
    malicious server. An attacker who successfully exploited
    this vulnerability could execute arbitrary code on the
    computer of the connecting client. An attacker could
    then install programs; view, change, or delete data; or
    create new accounts with full user rights.
    (CVE-2019-1333)

  - A remote code execution vulnerability exists when
    Internet Explorer improperly accesses objects in memory.
    The vulnerability could corrupt memory in such a way
    that an attacker could execute arbitrary code in the
    context of the current user. An attacker who
    successfully exploited the vulnerability could gain the
    same user rights as the current user.  (CVE-2019-1371)

  - An information disclosure vulnerability exists in the
    way that the Windows Code Integrity Module handles
    objects in memory. An attacker who successfully
    exploited this vulnerability could obtain information to
    further compromise the users system.  (CVE-2019-1344)

  - A remote code execution vulnerability exists when the
    Windows Imaging API improperly handles objects in
    memory. The vulnerability could corrupt memory in a way
    that enables an attacker to execute arbitrary code in
    the context of the current user.  (CVE-2019-1311)

  - A spoofing vulnerability exists when Transport Layer
    Security (TLS) accesses non- Extended Master Secret
    (EMS) sessions. An attacker who successfully exploited
    this vulnerability may gain access to unauthorized
    information.  (CVE-2019-1318)

  - An elevation of privilege vulnerability exists when
    Windows Error Reporting manager improperly handles a
    process crash. An attacker who successfully exploited
    this vulnerability could delete a targeted file leading
    to an elevated status.  (CVE-2019-1342)

  - A remote code execution vulnerability exists in the way
    that the VBScript engine handles objects in memory. The
    vulnerability could corrupt memory in such a way that an
    attacker could execute arbitrary code in the context of
    the current user. An attacker who successfully exploited
    the vulnerability could gain the same user rights as the
    current user.  (CVE-2019-1238)

  - A denial of service vulnerability exists in Remote
    Desktop Protocol (RDP) when an attacker connects to the
    target system using RDP and sends specially crafted
    requests. An attacker who successfully exploited this
    vulnerability could cause the RDP service on the target
    system to stop responding.  (CVE-2019-1326)

  - An elevation of privilege vulnerability exists in the
    Windows redirected drive buffering system (rdbss.sys)
    when the operating system improperly handles specific
    local calls within Windows 7 for 32-bit systems. When
    this vulnerability is exploited within other versions of
    Windows it can cause a denial of service, but not an
    elevation of privilege.  (CVE-2019-1325)

  - A tampering vulnerability exists in Microsoft Windows
    when a man-in-the-middle attacker is able to
    successfully bypass the NTLM MIC (Message Integrity
    Check) protection. An attacker who successfully
    exploited this vulnerability could gain the ability to
    downgrade NTLM security features.  (CVE-2019-1166)

  - An elevation of privilege vulnerability exists when
    umpo.dll of the Power Service, improperly handles a
    Registry Restore Key function. An attacker who
    successfully exploited this vulnerability could delete a
    targeted registry key leading to an elevated status.
    (CVE-2019-1341)

  - An elevation of privilege vulnerability exists when
    Windows Error Reporting manager improperly handles hard
    links. An attacker who successfully exploited this
    vulnerability could overwrite a targeted file leading to
    an elevated status.  (CVE-2019-1315, CVE-2019-1339)

  - An elevation of privilege vulnerability exists when
    Microsoft IIS Server fails to check the length of a
    buffer prior to copying memory to it. An attacker who
    successfully exploited this vulnerability can allow an
    unprivileged function ran by the user to execute code in
    the context of NT AUTHORITY\system escaping the Sandbox.
    The security update addresses the vulnerability by
    correcting how Microsoft IIS Server sanitizes web
    requests. (CVE-2019-1365)

  - A remote code execution vulnerability exists when the
    Microsoft XML Core Services MSXML parser processes user
    input. An attacker who successfully exploited the
    vulnerability could run malicious code remotely to take
    control of the users system.  (CVE-2019-1060)

  - An elevation of privilege vulnerability exists in
    Windows Error Reporting (WER) when WER handles and
    executes files. The vulnerability could allow elevation
    of privilege if an attacker can successfully exploit it.
    An attacker who successfully exploited the vulnerability
    could gain greater access to sensitive information and
    system functionality.  (CVE-2019-1319)

  - A spoofing vulnerability exists when Microsoft Browsers
    does not properly parse HTTP content. An attacker who
    successfully exploited this vulnerability could
    impersonate a user request by crafting HTTP queries. The
    specially crafted website could either spoof content or
    serve as a pivot to chain an attack with other
    vulnerabilities in web services.  (CVE-2019-0608)

  - A denial of service vulnerability exists when Windows
    improperly handles objects in memory. An attacker who
    successfully exploited the vulnerability could cause a
    target system to stop responding.  (CVE-2019-1343,
    CVE-2019-1346)");
  # https://support.microsoft.com/en-us/help/4520007/windows-server-2012-update-kb4520007
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7d72b58b");
  # https://support.microsoft.com/en-us/help/4519985/windows-server-2012-update-kb4519985
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e7951661");
  script_set_attribute(attribute:"solution", value:
"Apply Security Only update KB4519985 or Cumulative Update KB4520007.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1359");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-1365");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows_server_2012");
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

bulletin = "MS19-10";
kbs = make_list('4520007', '4519985');

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win8:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

# Windows 8 EOL
productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ("Windows 8" >< productname) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  smb_check_rollup(os:"6.2",
                   sp:0,
                   rollup_date:"10_2019",
                   bulletin:bulletin,
                   rollup_kb_list:[4520007, 4519985])
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
