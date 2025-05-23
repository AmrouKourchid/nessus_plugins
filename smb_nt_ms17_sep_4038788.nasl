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
  script_id(103130);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/17");

  script_cve_id(
    "CVE-2017-0161",
    "CVE-2017-8529",
    "CVE-2017-8597",
    "CVE-2017-8628",
    "CVE-2017-8643",
    "CVE-2017-8648",
    "CVE-2017-8649",
    "CVE-2017-8660",
    "CVE-2017-8675",
    "CVE-2017-8676",
    "CVE-2017-8677",
    "CVE-2017-8678",
    "CVE-2017-8679",
    "CVE-2017-8681",
    "CVE-2017-8682",
    "CVE-2017-8683",
    "CVE-2017-8687",
    "CVE-2017-8688",
    "CVE-2017-8692",
    "CVE-2017-8695",
    "CVE-2017-8699",
    "CVE-2017-8706",
    "CVE-2017-8707",
    "CVE-2017-8708",
    "CVE-2017-8709",
    "CVE-2017-8712",
    "CVE-2017-8713",
    "CVE-2017-8716",
    "CVE-2017-8719",
    "CVE-2017-8720",
    "CVE-2017-8723",
    "CVE-2017-8724",
    "CVE-2017-8728",
    "CVE-2017-8729",
    "CVE-2017-8733",
    "CVE-2017-8734",
    "CVE-2017-8735",
    "CVE-2017-8736",
    "CVE-2017-8737",
    "CVE-2017-8739",
    "CVE-2017-8740",
    "CVE-2017-8741",
    "CVE-2017-8746",
    "CVE-2017-8747",
    "CVE-2017-8748",
    "CVE-2017-8749",
    "CVE-2017-8750",
    "CVE-2017-8751",
    "CVE-2017-8752",
    "CVE-2017-8753",
    "CVE-2017-8754",
    "CVE-2017-8755",
    "CVE-2017-8756",
    "CVE-2017-8757",
    "CVE-2017-8759",
    "CVE-2017-11764",
    "CVE-2017-11766"
  );
  script_xref(name:"MSKB", value:"4038788");
  script_xref(name:"MSFT", value:"MS17-4038788");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");

  script_name(english:"KB4038788: Windows 10 Version 1703 September 2017 Cumulative Update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security update 4038788.
It is, therefore, affected by multiple vulnerabilities :

  - A race condition that could lead to a remote code
    execution vulnerability exists in NetBT Session Services
    when NetBT fails to maintain certain sequencing
    requirements. (CVE-2017-0161)

  - A vulnerability exists when Microsoft Edge improperly
    accesses objects in memory. The vulnerability could
    corrupt memory in such a way that an attacker could
    execute arbitrary code in the context of the current
    user. (CVE-2017-11766)

  - An information disclosure vulnerability exists when
    Microsoft Edge does not properly handle objects in
    memory. An attacker who successfully exploited the
    vulnerability could obtain information to further
    compromise the user's system.
    (CVE-2017-8597)

  - A spoofing vulnerability exists in Microsoft's
    implementation of the Bluetooth stack. An attacker who
    successfully exploited this vulnerability could perform
    a man-in-the-middle attack and force a user's computer
    to unknowingly route traffic through the attacker's
    computer. (CVE-2017-8628)

  - An information disclosure vulnerability exists when
    Microsoft Edge improperly handles clipboard events. For
    an attack to be successful, an attacker must persuade a
    user to visit a malicious website and leave it open
    during clipboard activities. The update addresses the
    vulnerability by changing how Microsoft Edge handles
    clipboard events in the browser. (CVE-2017-8643)

  - An information disclosure vulnerability exists when
    Microsoft Edge improperly handles objects in memory. An
    attacker who successfully exploited the vulnerability
    could obtain information to further compromise the users
    system. (CVE-2017-8648)

  - A remote code execution vulnerability exists in the way
    that Microsoft browser JavaScript engines render content
    when handling objects in memory. The vulnerability could
    corrupt memory in such a way that an attacker could
    execute arbitrary code in the context of the current
    user. (CVE-2017-8649)

  - A remote code execution vulnerability exists in the way
    that Microsoft browser JavaScript engines render content
    when handling objects in memory. The vulnerability could
    corrupt memory in such a way that an attacker could
    execute arbitrary code in the context of the current
    user. (CVE-2017-8649, CVE-2017-8660)

  - An elevation of privilege vulnerability exists in
    Windows when the Windows kernel-mode driver fails to
    properly handle objects in memory. An attacker who
    successfully exploited this vulnerability could run
    arbitrary code in kernel mode.
    (CVE-2017-8675)

  - An information disclosure vulnerability exists in the
    way that the Windows Graphics Device Interface (GDI)
    handles objects in memory, allowing an attacker to
    retrieve information from a targeted system. By itself,
    the information disclosure does not allow arbitrary code
    execution; however, it could allow arbitrary code to be
    run if the attacker uses it in combination with another
    vulnerability. (CVE-2017-8676)

  - A information disclosure vulnerability exists when the
    Windows GDI+ component improperly discloses kernel
    memory addresses. An attacker who successfully exploited
    the vulnerability could obtain information to further
    compromise the users system.(CVE-2017-8677)

  - An information disclosure vulnerability exists when the
    Windows kernel improperly handles objects in memory. An
    attacker who successfully exploited this vulnerability
    could obtain information to further compromise the users
    system. (CVE-2017-8678)

  - An information disclosure vulnerability exists when the
    Windows kernel improperly handles objects in memory. An
    attacker who successfully exploited this vulnerability
    could obtain information to further compromise the users
    system. (CVE-2017-8678, CVE-2017-8679)

  - A information disclosure vulnerability exists when the
    Windows GDI+ component improperly discloses kernel
    memory addresses. An attacker who successfully exploited
    the vulnerability could obtain information to further
    compromise the users system.
    (CVE-2017-8677, CVE-2017-8681)

  - A remote code execution vulnerability exists when the
    Windows font library improperly handles specially
    crafted embedded fonts. An attacker who successfully
    exploited this vulnerability could take control of the
    affected system. An attacker could then install
    programs; view, change, or delete data; or create new
    accounts with full user rights. (CVE-2017-8682)

  - An information disclosure vulnerability exists when the
    Microsoft Windows Graphics Component improperly handles
    objects in memory. An attacker who successfully
    exploited the vulnerability could obtain information to
    further compromise the users system. (CVE-2017-8683)

  - An Information disclosure vulnerability exists in
    Windows kernel that could allow an attacker to retrieve
    information that could lead to a Kernel Address Space
    Layout Randomization (KASLR) bypass. An attacker who
    successfully exploited this vulnerability could retrieve
    the memory address of a kernel object.(CVE-2017-8687)

  - An information disclosure vulnerability exists in the
    way that the Windows Graphics Device Interface+ (GDI+)
    handles objects in memory, allowing an attacker to
    retrieve information from a targeted system. By itself,
    the information disclosure does not allow arbitrary code
    execution; however, it could allow arbitrary code to be
    run if the attacker uses it in combination with another
    vulnerability.(CVE-2017-8688)

  - A remote code execution vulnerability exists due to the
    way Windows Uniscribe handles objects in memory. An
    attacker who successfully exploited this vulnerability
    could take control of the affected system. An attacker
    could then install programs; view, change, or delete
    data; or create new accounts with full user rights.
    (CVE-2017-8692)

  - An information disclosure vulnerability exists when
    Windows Uniscribe improperly discloses the contents of
    its memory. An attacker who successfully exploited the
    vulnerability could obtain information to further
    compromise the users system. (CVE-2017-8695)

  - A remote code execution vulnerability exists when
    Windows Shell does not properly validate file copy
    destinations. An attacker who successfully exploited the
    vulnerability could run arbitrary code in the context of
    the current user.
    (CVE-2017-8699)

  - An information disclosure vulnerability exists when
    Windows Hyper-V on a host operating system fails to
    properly validate input from an authenticated user on a
    guest operating system.
    (CVE-2017-8706)

  - An information disclosure vulnerability exists when
    Windows Hyper-V on a host operating system fails to
    properly validate input from an authenticated user on a
    guest operating system.
    (CVE-2017-8706, CVE-2017-8707)

  - An information disclosure vulnerability exists when the
    Windows kernel fails to properly initialize a memory
    address, allowing an attacker to retrieve information
    that could lead to a Kernel Address Space Layout
    Randomization (KASLR) bypass. (CVE-2017-8708)

  - An information disclosure vulnerability exists when the
    Windows kernel improperly handles objects in memory. An
    attacker who successfully exploited this vulnerability
    could obtain information to further compromise the users
    system. (CVE-2017-8678, CVE-2017-8679, CVE-2017-8709)

  - An information disclosure vulnerability exists when
    Windows Hyper-V on a host operating system fails to
    properly validate input from an authenticated user on a
    guest operating system.
    (CVE-2017-8706, CVE-2017-8707, CVE-2017-8712)

  - An information disclosure vulnerability exists when
    Windows Hyper-V on a host operating system fails to
    properly validate input from an authenticated user on a
    guest operating system. (CVE-2017-8706, CVE-2017-8707, 
    CVE-2017-8712,CVE-2017-8713)

  - A security feature bypass vulnerability exists when
    Windows Control Flow Guard mishandles objects in memory.
    (CVE-2017-8716)

  - An information disclosure vulnerability exists when the
    Windows kernel improperly handles objects in memory. An
    attacker who successfully exploited this vulnerability
    could obtain information to further compromise the users
    system. (CVE-2017-8678, CVE-2017-8679, CVE-2017-8709,
    CVE-2017-8719)

  - An elevation of privilege vulnerability exists in
    Windows when the Win32k component fails to properly
    handle objects in memory. (CVE-2017-8720)

  - A security feature bypass exists in Microsoft Edge when
    the Edge Content Security Policy (CSP) fails to properly
    validate certain specially crafted documents. An
    attacker who exploited the bypass could trick a user
    into loading a page containing malicious content.
    (CVE-2017-8723)

  - A spoofing vulnerability exists when Microsoft Edge does
    not properly parse HTTP content. (CVE-2017-8724)

  - A remote code execution vulnerability exists when
    Microsoft Windows PDF Library improperly handles objects
    in memory. The vulnerability could corrupt memory in a
    way that enables an attacker to execute arbitrary code
    in the context of the current user. An attacker who
    successfully exploited the vulnerability could gain the
    same user rights as the current user.
    (CVE-2017-8728)

  - A spoofing vulnerability exists when Internet Explorer
    improperly handles specific HTML content. An attacker
    who successfully exploited this vulnerability could
    trick a user into believing that the user was visiting a
    legitimate website. The specially crafted website could
    either spoof content or serve as a pivot to chain an
    attack with other vulnerabilities in web services. To
    exploit the vulnerability, the user must either browse
    to a malicious website or be redirected to it.
    (CVE-2017-8733)

  - A remote code execution vulnerability exists when
    Microsoft Edge improperly accesses objects in memory.
    The vulnerability could corrupt memory in such a way
    that enables an attacker to execute arbitrary code in
    the context of the current user. An attacker who
    successfully exploited the vulnerability could gain the
    same user rights as the current user. (CVE-2017-8734)

  - A spoofing vulnerability exists when Microsoft Edge does
    not properly parse HTTP content. An attacker who
    successfully exploited this vulnerability could trick a
    user by redirecting the user to a specially crafted
    website. The specially crafted website could either
    spoof content or serve as a pivot to chain an attack
    with other vulnerabilities in web services.
    (CVE-2017-8724, CVE-2017-8735)

  - An information disclosure vulnerability exists in
    Microsoft browsers due to improper parent domain
    verification in certain functionality. An attacker who
    successfully exploited the vulnerability could obtain
    specific information that is used in the parent domain.
    (CVE-2017-8736)

  - A remote code execution vulnerability exists when
    Microsoft Windows PDF Library improperly handles objects
    in memory. The vulnerability could corrupt memory in a
    way that enables an attacker to execute arbitrary code
    in the context of the current user. An attacker who
    successfully exploited the vulnerability could gain the
    same user rights as the current user.
    (CVE-2017-8728, CVE-2017-8737)

  - An information disclosure vulnerability exists when the
    scripting engine does not properly handle objects in
    memory in Microsoft Edge. (CVE-2017-8739)

  - A remote code execution vulnerability exists in the way
    that Microsoft browser JavaScript engines render content
    when handling objects in memory. The vulnerability could
    corrupt memory in such a way that an attacker could
    execute arbitrary code in the context of the current
    user.(CVE-2017-8649, CVE-2017-8660, CVE-2017-8741)

  - A security feature bypass vulnerability exists in Device
    Guard that could allow an attacker to inject malicious
    code into a Windows PowerShell session. An attacker who
    successfully exploited this vulnerability could inject
    code into a trusted PowerShell process to bypass the
    Device Guard Code Integrity policy on the local machine.
    (CVE-2017-8746)

  - A remote code execution vulnerability exists when
    Internet Explorer improperly accesses objects in memory.
    The vulnerability could corrupt memory in such a way
    that an attacker could execute arbitrary code in the
    context of the current user.(CVE-2017-8747)

  - A remote code execution vulnerability exists in the way
    that Microsoft browser JavaScript engines render content
    when handling objects in memory. The vulnerability could
    corrupt memory in such a way that an attacker could
    execute arbitrary code in the context of the current
    user. (CVE-2017-8649, CVE-2017-8660, CVE-2017-8741,
    CVE-2017-8748)

  - A remote code execution vulnerability exists when
    Internet Explorer improperly accesses objects in memory.
    The vulnerability could corrupt memory in such a way
    that an attacker could execute arbitrary code in the
    context of the current user.(CVE-2017-8747,
    CVE-2017-8749)

  - A remote code execution vulnerability exists when
    Microsoft browsers improperly access objects in memory.
    The vulnerability could corrupt memory in such a way
    that an attacker could execute arbitrary code in the
    context of the current user. (CVE-2017-8750)

  - A remote code execution vulnerability exists when
    Microsoft Edge improperly accesses objects in memory.
    The vulnerability could corrupt memory in such a way
    that enables an attacker to execute arbitrary code in
    the context of the current user. An attacker who
    successfully exploited the vulnerability could gain the
    same user rights as the current user.
    (CVE-2017-8734, CVE-2017-8751)

  - A security feature bypass exists in Microsoft Edge when
    the Edge Content Security Policy (CSP) fails to properly
    validate certain specially crafted documents. An
    attacker who exploited the bypass could trick a user
    into loading a page containing malicious content. To
    exploit the bypass, an attacker must trick a user into
    either loading a page containing malicious content or
    visiting a malicious website. The attacker could also
    inject the malicious page into either a compromised
    website or an advertisement network. The update
    addresses the bypass by correcting how the Edge CSP
    validates documents. (CVE-2017-8723, CVE-2017-8754)

  - A remote code execution vulnerability exists in the way
    that the scripting engine handles objects in memory in
    Microsoft Edge. The vulnerability could corrupt memory
    in such a way that an attacker could execute arbitrary
    code in the context of the current user. An attacker who
    successfully exploited the vulnerability could gain the
    same user rights as the current user.
    (CVE-2017-11764, CVE-2017-8729, CVE-2017-8740,
    CVE-2017-8752, CVE-2017-8753, CVE-2017-8755,
    CVE-2017-8756)

  - A remote code execution vulnerability exists in the way
    Microsoft Edge handles objects in memory. The
    vulnerability could corrupt memory in such a way that an
    attacker could execute arbitrary code in the context of
    the current user. (CVE-2017-8757)

  - A remote code execution vulnerability exists when
    Microsoft .NET Framework processes untrusted input. An
    attacker who successfully exploited this vulnerability
    in software using the .NET framework could take control
    of an affected system. An attacker could then install
    programs; view, change, or delete data; or create new
    accounts with full user rights.
    (CVE-2017-8759)
    
  - An information disclosure vulnerability exists in
    Microsoft browsers in the scripting engines due to
    improper handling of objects in memory. An
    unauthenticated, remote attacker can exploit this, by
    convincing a user to visit a specially crafted website,
    to disclose files on a user's computer. (CVE-2017-8529)");
  # https://support.microsoft.com/en-us/help/4038788/windows-10-update-kb4038788
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fb942e3e");
  script_set_attribute(attribute:"solution", value:
"Apply security update KB4038788.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-8759");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2017-8682");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows_10_1703");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2017-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

bulletin = "MS17-09";
kbs = make_list('4038788');

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  smb_check_rollup(os:"10",
                   sp:0,
                   os_build:"15063",
                   rollup_date:"09_2017",
                   bulletin:bulletin,
                   rollup_kb_list:[4038788])
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
