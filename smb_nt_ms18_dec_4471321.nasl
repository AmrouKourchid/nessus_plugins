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
  script_id(119584);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/08");

  script_cve_id(
    "CVE-2018-8477",
    "CVE-2018-8514",
    "CVE-2018-8517",
    "CVE-2018-8540",
    "CVE-2018-8595",
    "CVE-2018-8596",
    "CVE-2018-8599",
    "CVE-2018-8611",
    "CVE-2018-8612",
    "CVE-2018-8617",
    "CVE-2018-8618",
    "CVE-2018-8619",
    "CVE-2018-8624",
    "CVE-2018-8625",
    "CVE-2018-8626",
    "CVE-2018-8629",
    "CVE-2018-8631",
    "CVE-2018-8634",
    "CVE-2018-8639",
    "CVE-2018-8641",
    "CVE-2018-8643"
  );
  script_xref(name:"MSKB", value:"4471321");
  script_xref(name:"MSFT", value:"MS18-4471321");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2025/03/24");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/14");

  script_name(english:"KB4471321: Windows 10 Version 1607 and Windows Server 2016 December 2018 Security Update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security update 4471321.
It is, therefore, affected by multiple vulnerabilities :

  - A remote code execution vulnerability exists when the
    Microsoft .NET Framework fails to validate input
    properly. An attacker who successfully exploited this
    vulnerability could take control of an affected system.
    An attacker could then install programs; view, change,
    or delete data; or create new accounts with full user
    rights. Users whose accounts are configured to have
    fewer user rights on the system could be less impacted
    than users who operate with administrative user rights.
    (CVE-2018-8540)

  - A Denial Of Service vulnerability exists when Connected
    User Experiences and Telemetry Service fails to validate
    certain function values. An attacker who successfully
    exploited this vulnerability could deny dependent
    security feature functionality.  (CVE-2018-8612)

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
    in memory. (CVE-2018-8595, CVE-2018-8596)

  - A remote code execution vulnerability exists in Windows
    where Microsoft text-to-speech fails to properly handle
    objects in the memory. An attacker who successfully
    exploited this vulnerability could take control of the
    affected system. An attacker could then install
    programs; view, change, or delete data; or create new
    accounts with full user rights.  (CVE-2018-8634)

  - A remote code execution vulnerability exists when
    Internet Explorer improperly accesses objects in memory.
    The vulnerability could corrupt memory in such a way
    that an attacker could execute arbitrary code in the
    context of the current user. An attacker who
    successfully exploited the vulnerability could gain the
    same user rights as the current user.  (CVE-2018-8631)

  - An elevation of privilege vulnerability exists in
    Windows when the Win32k component fails to properly
    handle objects in memory. An attacker who successfully
    exploited this vulnerability could run arbitrary code in
    kernel mode. An attacker could then install programs;
    view, change, or delete data; or create new accounts
    with full user rights.  (CVE-2018-8639)

  - An elevation of privilege vulnerability exists when the
    Diagnostics Hub Standard Collector Service improperly
    impersonates certain file operations. An attacker who
    successfully exploited this vulnerability could gain
    elevated privileges. An attacker with unprivileged
    access to a vulnerable system could exploit this
    vulnerability. The security update addresses the
    vulnerability by ensuring the Diagnostics Hub Standard
    Collector Service properly impersonates file operations.
    (CVE-2018-8599)

  - An information disclosure vulnerability exists when the
    Windows kernel improperly handles objects in memory. An
    attacker who successfully exploited this vulnerability
    could obtain information to further compromise the users
    system.  (CVE-2018-8477)

  - An information disclosure vulnerability exists when
    Remote Procedure Call runtime improperly initializes
    objects in memory.  (CVE-2018-8514)

  - A remote code execution vulnerability exists in the way
    that the Chakra scripting engine handles objects in
    memory in Microsoft Edge. The vulnerability could
    corrupt memory in such a way that an attacker could
    execute arbitrary code in the context of the current
    user. An attacker who successfully exploited the
    vulnerability could gain the same user rights as the
    current user.  (CVE-2018-8617, CVE-2018-8618,
    CVE-2018-8624, CVE-2018-8629)

  - An elevation of privilege vulnerability exists when the
    Windows kernel fails to properly handle objects in
    memory. An attacker who successfully exploited this
    vulnerability could run arbitrary code in kernel mode.
    An attacker could then install programs; view, change,
    or delete data; or create new accounts with full user
    rights.  (CVE-2018-8611)

  - A remote code execution vulnerability exists in the way
    that the VBScript engine handles objects in memory. The
    vulnerability could corrupt memory in such a way that an
    attacker could execute arbitrary code in the context of
    the current user. An attacker who successfully exploited
    the vulnerability could gain the same user rights as the
    current user.  (CVE-2018-8625)

  - A remote code execution vulnerability exists when the
    Internet Explorer VBScript execution policy does not
    properly restrict VBScript under specific conditions. An
    attacker who exploited the vulnerability could run
    arbitrary code with medium-integrity level privileges
    (the permissions of the current user).  (CVE-2018-8619)

  - A remote code execution vulnerability exists in the way
    that the scripting engine handles objects in memory in
    Internet Explorer. The vulnerability could corrupt
    memory in such a way that an attacker could execute
    arbitrary code in the context of the current user. An
    attacker who successfully exploited the vulnerability
    could gain the same user rights as the current user.
    (CVE-2018-8643)

  - A denial of service vulnerability exists when .NET
    Framework improperly handles special web requests. An
    attacker who successfully exploited this vulnerability
    could cause a denial of service against an .NET
    Framework web application. The vulnerability can be
    exploited remotely, without authentication. A remote
    unauthenticated attacker could exploit this
    vulnerability by issuing specially crafted requests to
    the .NET Framework application. The update addresses the
    vulnerability by correcting how the .NET Framework web
    application handles web requests. (CVE-2018-8517)

  - An elevation of privilege vulnerability exists in
    Windows when the Windows kernel-mode driver fails to
    properly handle objects in memory. An attacker who
    successfully exploited this vulnerability could run
    arbitrary code in kernel mode. An attacker could then
    install programs; view, change, or delete data; or
    create new accounts with full user rights.
    (CVE-2018-8641)

  - A remote code execution vulnerability exists in Windows
    Domain Name System (DNS) servers when they fail to
    properly handle requests. An attacker who successfully
    exploited the vulnerability could run arbitrary code in
    the context of the Local System Account. Windows servers
    that are configured as DNS servers are at risk from this
    vulnerability.  (CVE-2018-8626)");
  # https://support.microsoft.com/en-us/help/4471321/windows-10-update-kb4471321
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?417b4781");
  script_set_attribute(attribute:"solution", value:
"Apply Cumulative Update KB4471321.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8626");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/11");

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

bulletin = "MS18-12";
kbs = make_list('4471321');

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  smb_check_rollup(os:"10",
                   sp:0,
                   os_build:"14393",
                   rollup_date:"12_2018",
                   bulletin:bulletin,
                   rollup_kb_list:[4471321])
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
