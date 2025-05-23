#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
#
include("compat.inc");

if (description)
{
  script_id(102268);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/18");

  script_cve_id(
    "CVE-2017-0174",
    "CVE-2017-0250",
    "CVE-2017-0293",
    "CVE-2017-8591",
    "CVE-2017-8593",
    "CVE-2017-8620",
    "CVE-2017-8624",
    "CVE-2017-8633",
    "CVE-2017-8635",
    "CVE-2017-8636",
    "CVE-2017-8641",
    "CVE-2017-8651",
    "CVE-2017-8653",
    "CVE-2017-8664",
    "CVE-2017-8666",
    "CVE-2017-8668"
  );
  script_bugtraq_id(
    98100,
    99430,
    100032,
    100034,
    100038,
    100039,
    100055,
    100056,
    100057,
    100058,
    100059,
    100061,
    100069,
    100085,
    100089,
    100092
  );
  script_xref(name:"MSKB", value:"4034665");
  script_xref(name:"MSFT", value:"MS17-4034665");
  script_xref(name:"MSKB", value:"4034666");
  script_xref(name:"MSFT", value:"MS17-4034666");

  script_name(english:"Windows Server 2012 August 2017 Security Updates");
  script_summary(english:"Checks for rollup.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security update 4034666
or cumulative update 4034665. It is, therefore, affected by
multiple vulnerabilities :

  - A denial of service vulnerability exists when Microsoft
    Windows improperly handles NetBIOS packets. An attacker
    who successfully exploited this vulnerability could
    cause a target computer to become completely
    unresponsive. A remote unauthenticated attacker could
    exploit this vulnerability by sending a series of TCP
    packets to a target system, resulting in a permanent
    denial of service condition. The update addresses the
    vulnerability by correcting how the Windows network
    stack handles NetBIOS traffic. (CVE-2017-0174)

  - A buffer overflow vulnerability exists in the Microsoft
    JET Database Engine that could allow remote code
    execution on an affected system. An attacker who
    successfully exploited this vulnerability could take
    complete control of an affected system. An attacker
    could then install programs; view, change, or delete
    data; or create new accounts with full user rights.
    (CVE-2017-0250)

  - A remote code execution vulnerability exists when
    Microsoft Windows PDF Library improperly handles objects
    in memory. The vulnerability could corrupt memory in a
    way that enables an attacker to execute arbitrary code
    in the context of the current user. An attacker who
    successfully exploited the vulnerability could gain the
    same user rights as the current user. (CVE-2017-0293)

  - A remote code execution vulnerability exists in Windows
    Input Method Editor (IME) when IME improperly handles
    parameters in a method of a DCOM class. The DCOM server
    is a Windows component installed regardless of which
    languages/IMEs are enabled. An attacker can instantiate
    the DCOM class and exploit the system even if IME is not
    enabled. (CVE-2017-8591)

  - An elevation of privilege vulnerability exists in
    Windows when the Win32k component fails to properly
    handle objects in memory. An attacker who successfully
    exploited this vulnerability could run arbitrary code in
    kernel mode. An attacker could then install programs;
    view, change, or delete data; or create new accounts
    with full user rights. (CVE-2017-8593)

  - A remote code execution vulnerability exists when
    Windows Search handles objects in memory. An attacker
    who successfully exploited this vulnerability could take
    control of the affected system. An attacker could then
    install programs; view, change, or delete data; or
    create new accounts with full user rights.To exploit the
    vulnerability, the attacker could send specially crafted
    messages to the Windows Search service. An attacker with
    access to a target computer could exploit this
    vulnerability to elevate privileges and take control of
    the computer. Additionally, in an enterprise scenario, a
    remote unauthenticated attacker could remotely trigger
    the vulnerability through an SMB connection and then
    take control of a target computer.The security update
    addresses the vulnerability by correcting how Windows
    Search handles objects in memory. (CVE-2017-8620)

  - An elevation of privilege vulnerability exists when the
    Windows Common Log File System (CLFS) driver improperly
    handles objects in memory. (CVE-2017-8624)

  - This security update resolves a vulnerability in Windows
    Error Reporting (WER). The vulnerability could allow
    elevation of privilege if successfully exploited by an
    attacker. An attacker who successfully exploited this
    vulnerability could gain greater access to sensitive
    information and system functionality. This update
    corrects the way the WER handles and executes files.
    (CVE-2017-8633)

  - A remote code execution vulnerability exists in the way
    JavaScript engines render when handling objects in
    memory in Microsoft browsers. The vulnerability could
    corrupt memory in such a way that an attacker could
    execute arbitrary code in the context of the current
    user. An attacker who successfully exploited the
    vulnerability could gain the same user rights as the
    current user. (CVE-2017-8635)

  - A remote code execution vulnerability exists in the way
    that Microsoft browser JavaScript engines render content
    when handling objects in memory. The vulnerability could
    corrupt memory in such a way that an attacker could
    execute arbitrary code in the context of the current
    user. (CVE-2017-8636)

  - A remote code execution vulnerability exists in the way
    JavaScript engines render when handling objects in
    memory in Microsoft browsers. The vulnerability could
    corrupt memory in such a way that an attacker could
    execute arbitrary code in the context of the current
    user. An attacker who successfully exploited the
    vulnerability could gain the same user rights as the
    current user. (CVE-2017-8641)

  - A remote code execution vulnerability exists when
    Internet Explorer improperly accesses objects in memory.
    The vulnerability could corrupt memory in such a way
    that an attacker could execute arbitrary code in the
    context of the current user. An attacker who
    successfully exploited the vulnerability could gain the
    same user rights as the current user. (CVE-2017-8651)

  - A remote code execution vulnerability exists when
    Microsoft browsers improperly access objects in memory.
    The vulnerability could corrupt memory in such a way
    that enables an attacker to execute arbitrary code in
    the context of the current user. An attacker who
    successfully exploited the vulnerability could gain the
    same user rights as the current user. (CVE-2017-8653)

  - A remote code execution vulnerability exists when
    Windows Hyper-V on a host server fails to properly
    validate input from an authenticated user on a guest
    operating system. (CVE-2017-8664)

  - An information disclosure vulnerability exists when the
    win32k component improperly provides kernel information.
    An attacker who successfully exploited the vulnerability
    could obtain information to further compromise the users
    system. (CVE-2017-8666)

  - An information disclosure vulnerability exists when the
    Volume Manager Extension Driver component improperly
    provides kernel information. An attacker who
    successfully exploited the vulnerability could obtain
    information to further compromise the users system.To
    exploit this vulnerability, an attacker would have to
    log on to an affected system and run a specially crafted
    application.The security update addresses the
    vulnerability by correcting how Volume Manager Extension
    Driver handles objects in memory. (CVE-2017-8668)");
  # https://support.microsoft.com/en-us/help/4034665/windows-server-2012-update-kb4034665
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5a9af664");
  # https://support.microsoft.com/en-us/help/4034666/windows-server-2012-update-kb4034666
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bb07fa4c");
  script_set_attribute(attribute:"solution", value:
"Apply Security Only update KB4034666 or Cumulative update KB4034665.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-8620");
  script_set_attribute(attribute: "cvss3_score_source", value: "manual");
  script_set_attribute(attribute:"cvss3_score_rationale", value:"Scoring adjustsed to align with CVSS 3.1 attack complexity guidance.");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows_server_2012");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2017-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

bulletin = "MS17-08";
kbs = make_list('4034665', '4034666');

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
                   rollup_date:"08_2017",
                   bulletin:bulletin,
                   rollup_kb_list:[4034665, 4034666])
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
