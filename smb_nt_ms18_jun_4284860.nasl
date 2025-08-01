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
  script_id(110489);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/01");

  script_cve_id(
    "CVE-2018-0978",
    "CVE-2018-1036",
    "CVE-2018-1040",
    "CVE-2018-8169",
    "CVE-2018-8201",
    "CVE-2018-8205",
    "CVE-2018-8207",
    "CVE-2018-8209",
    "CVE-2018-8210",
    "CVE-2018-8212",
    "CVE-2018-8213",
    "CVE-2018-8215",
    "CVE-2018-8216",
    "CVE-2018-8217",
    "CVE-2018-8221",
    "CVE-2018-8225",
    "CVE-2018-8226",
    "CVE-2018-8229",
    "CVE-2018-8231",
    "CVE-2018-8234",
    "CVE-2018-8235",
    "CVE-2018-8236",
    "CVE-2018-8251",
    "CVE-2018-8267"
  );
  script_bugtraq_id(
    104328,
    104331,
    104333,
    104334,
    104336,
    104337,
    104338,
    104340,
    104343,
    104356,
    104360,
    104361,
    104364,
    104369,
    104373,
    104379,
    104389,
    104391,
    104393,
    104395,
    104398,
    104404,
    104406,
    104407
  );
  script_xref(name:"MSKB", value:"4284860");
  script_xref(name:"MSFT", value:"MS18-4284860");

  script_name(english:"KB4284860: Windows 10 June 2018 Security Update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security update 4284860.
It is, therefore, affected by multiple vulnerabilities :

  - An elevation of privilege vulnerability exists when the
    (Human Interface Device) HID Parser Library driver
    improperly handles objects in memory. An attacker who
    successfully exploited this vulnerability could run
    processes in an elevated context.  (CVE-2018-8169)

  - An information disclosure vulnerability exists when
    Microsoft Edge improperly handles objects in memory. An
    attacker who successfully exploited the vulnerability
    could obtain information to further compromise the users
    system.  (CVE-2018-8234)

  - A memory corruption vulnerability exists when Windows
    Media Foundation improperly handles objects in memory.
    An attacker who successfully exploited the vulnerability
    could install programs; view, change, or delete data; or
    create new accounts with full user rights. There are
    multiple ways an attacker could exploit the
    vulnerability, such as by convincing a user to open a
    specially crafted document, or by convincing a user to
    visit a malicious webpage. The security update addresses
    the vulnerability by correcting how Windows Media
    Foundation handles objects in memory. (CVE-2018-8251)

  - A remote code execution vulnerability exists in Windows
    Domain Name System (DNS) DNSAPI.dll when it fails to
    properly handle DNS responses. An attacker who
    successfully exploited the vulnerability could run
    arbitrary code in the context of the Local System
    Account.  (CVE-2018-8225)

  - A remote code execution vulnerability exists when
    Microsoft Edge improperly accesses objects in memory.
    The vulnerability could corrupt memory in such a way
    that enables an attacker to execute arbitrary code in
    the context of the current user. An attacker who
    successfully exploited the vulnerability could gain the
    same user rights as the current user.  (CVE-2018-8236)

  - A security feature bypass vulnerability exists when
    Microsoft Edge improperly handles requests of different
    origins. The vulnerability allows Microsoft Edge to
    bypass Same-Origin Policy (SOP) restrictions, and to
    allow requests that should otherwise be ignored. An
    attacker who successfully exploited the vulnerability
    could force the browser to send data that would
    otherwise be restricted.  (CVE-2018-8235)

  - A denial of service vulnerability exists in the HTTP 2.0
    protocol stack (HTTP.sys) when HTTP.sys improperly
    parses specially crafted HTTP 2.0 requests. An attacker
    who successfully exploited the vulnerability could
    create a denial of service condition, causing the target
    system to become unresponsive.  (CVE-2018-8226)

  - A remote code execution vulnerability exists in the way
    that the Chakra scripting engine handles objects in
    memory in Microsoft Edge. The vulnerability could
    corrupt memory in such a way that an attacker could
    execute arbitrary code in the context of the current
    user. An attacker who successfully exploited the
    vulnerability could gain the same user rights as the
    current user.  (CVE-2018-8229)

  - A remote code execution vulnerability exists in the way
    that the scripting engine handles objects in memory in
    Internet Explorer. The vulnerability could corrupt
    memory in such a way that an attacker could execute
    arbitrary code in the context of the current user. An
    attacker who successfully exploited the vulnerability
    could gain the same user rights as the current user.
    (CVE-2018-8267)

  - A denial of service vulnerability exists in the way that
    the Windows Code Integrity Module performs hashing. An
    attacker who successfully exploited the vulnerability
    could cause a system to stop responding. Note that the
    denial of service condition would not allow an attacker
    to execute code or to elevate user privileges. However,
    the denial of service condition could prevent authorized
    users from using system resources. An attacker could
    host a specially crafted file in a website or SMB share.
    The attacker could also take advantage of compromised
    websites, or websites that accept or host user-provided
    content or advertisements, by adding specially crafted
    content that could exploit the vulnerability. However,
    in all cases an attacker would have no way to force
    users to view the attacker-controlled content. Instead,
    an attacker would have to convince users to take action,
    typically via an enticement in email or instant message,
    or by getting them to open an email attachment. The
    security update addresses the vulnerability by modifying
    how the Code Integrity Module performs hashing.
    (CVE-2018-1040)

  - A denial of service vulnerability exists when Windows
    improperly handles objects in memory. An attacker who
    successfully exploited the vulnerability could cause a
    target system to stop responding.  (CVE-2018-8205)

  - An information disclosure vulnerability exists when
    Windows allows a normal user to access the Wireless LAN
    profile of an administrative user. An authenticated
    attacker who successfully exploited the vulnerability
    could access the Wireless LAN profile of an
    administrative user, including passwords for wireless
    networks. An attacker would need to log on to the
    affected system and run a specific command. The security
    update addresses the vulnerability by changing the way
    that Windows enforces access permissions to Wireless LAN
    profiles. (CVE-2018-8209)

  - A remote code execution vulnerability exists when
    Internet Explorer improperly accesses objects in memory.
    The vulnerability could corrupt memory in such a way
    that an attacker could execute arbitrary code in the
    context of the current user. An attacker who
    successfully exploited the vulnerability could gain the
    same user rights as the current user.  (CVE-2018-0978)

  - An information disclosure vulnerability exists when the
    Windows kernel improperly handles objects in memory. An
    attacker who successfully exploited this vulnerability
    could obtain information to further compromise the users
    system.  (CVE-2018-8207)

  - A security feature bypass vulnerability exists in Device
    Guard that could allow an attacker to inject malicious
    code into a Windows PowerShell session. An attacker who
    successfully exploited this vulnerability could inject
    code into a trusted PowerShell process to bypass the
    Device Guard Code Integrity policy on the local machine.
    (CVE-2018-8201, CVE-2018-8212, CVE-2018-8215,
    CVE-2018-8216, CVE-2018-8217, CVE-2018-8221)

  - A remote code execution vulnerability exists when HTTP
    Protocol Stack (Http.sys) improperly handles objects in
    memory. An attacker who successfully exploited this
    vulnerability could execute arbitrary code and take
    control of the affected system.  (CVE-2018-8231)

  - A remote code execution vulnerability exists when
    Windows improperly handles objects in memory. An
    attacker who successfully exploited these
    vulnerabilities could take control of an affected
    system.  (CVE-2018-8210, CVE-2018-8213)

  - An elevation of privilege vulnerability exists when NTFS
    improperly checks access. An attacker who successfully
    exploited this vulnerability could run processes in an
    elevated context.  (CVE-2018-1036)");
  # https://support.microsoft.com/en-us/help/4284860/windows-10-update-kb4284860
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?686a6741");
  script_set_attribute(attribute:"solution", value:
"Apply Cumulative Update KB4284860.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8231");
  script_set_attribute(attribute:"cvss3_score_rationale", value:"Scoring adjustsed to align with CVSS 3.1 attack complexity guidance.");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:edge");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2018-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

bulletin = "MS18-06";
kbs = make_list('4284860');

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  smb_check_rollup(os:"10",
                   sp:0,
                   os_build:"10240",
                   rollup_date:"06_2018",
                   bulletin:bulletin,
                   rollup_kb_list:[4284860])
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
