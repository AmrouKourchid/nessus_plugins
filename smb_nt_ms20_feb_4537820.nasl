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
  script_id(134864);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/17");

  script_cve_id(
    "CVE-2020-0655",
    "CVE-2020-0657",
    "CVE-2020-0658",
    "CVE-2020-0662",
    "CVE-2020-0665",
    "CVE-2020-0666",
    "CVE-2020-0667",
    "CVE-2020-0668",
    "CVE-2020-0673",
    "CVE-2020-0674",
    "CVE-2020-0675",
    "CVE-2020-0676",
    "CVE-2020-0677",
    "CVE-2020-0678",
    "CVE-2020-0680",
    "CVE-2020-0681",
    "CVE-2020-0682",
    "CVE-2020-0683",
    "CVE-2020-0686",
    "CVE-2020-0691",
    "CVE-2020-0698",
    "CVE-2020-0703",
    "CVE-2020-0705",
    "CVE-2020-0708",
    "CVE-2020-0715",
    "CVE-2020-0719",
    "CVE-2020-0720",
    "CVE-2020-0721",
    "CVE-2020-0722",
    "CVE-2020-0723",
    "CVE-2020-0724",
    "CVE-2020-0725",
    "CVE-2020-0726",
    "CVE-2020-0729",
    "CVE-2020-0730",
    "CVE-2020-0731",
    "CVE-2020-0734",
    "CVE-2020-0735",
    "CVE-2020-0736",
    "CVE-2020-0737",
    "CVE-2020-0738",
    "CVE-2020-0744",
    "CVE-2020-0745",
    "CVE-2020-0748",
    "CVE-2020-0752",
    "CVE-2020-0753",
    "CVE-2020-0754",
    "CVE-2020-0755",
    "CVE-2020-0756"
  );
  script_xref(name:"MSKB", value:"4537820");
  script_xref(name:"MSKB", value:"4537813");
  script_xref(name:"MSFT", value:"MS20-4537820");
  script_xref(name:"MSFT", value:"MS20-4537813");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");
  script_xref(name:"CEA-ID", value:"CEA-2020-0010");
  script_xref(name:"CEA-ID", value:"CEA-2020-0019");

  script_name(english:"KB4537813: Windows 7 and Windows Server 2008 R2 February 2020 Security Update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security update 4537813
or cumulative update 4537820. It is, therefore, affected by
multiple vulnerabilities :

  - A remote code execution vulnerability exists in the
    Windows Remote Desktop Client when a user connects to a
    malicious server. An attacker who successfully exploited
    this vulnerability could execute arbitrary code on the
    computer of the connecting client. An attacker could
    then install programs; view, change, or delete data; or
    create new accounts with full user rights.
    (CVE-2020-0681, CVE-2020-0734)

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
    Foundation handles objects in memory. (CVE-2020-0738)

  - An information disclosure vulnerability exists in the
    Windows Common Log File System (CLFS) driver when it
    fails to properly handle objects in memory. An attacker
    who successfully exploited this vulnerability could
    potentially read data that was not intended to be
    disclosed. Note that this vulnerability would not allow
    an attacker to execute code or to elevate their user
    rights directly, but it could be used to obtain
    information that could be used to try to further
    compromise the affected system.  (CVE-2020-0658)

  - An elevation of privilege vulnerability exists in the
    way that the tapisrv.dll handles objects in memory. An
    attacker who successfully exploited the vulnerability
    could execute code with elevated permissions.
    (CVE-2020-0737)

  - An elevation of privilege vulnerability exists in the
    way that the Windows Kernel handles objects in memory.
    An attacker who successfully exploited the vulnerability
    could execute code with elevated permissions.
    (CVE-2020-0668)

  - An information disclosure vulnerability exists in the
    Cryptography Next Generation (CNG) service when it fails
    to properly handle objects in memory.  (CVE-2020-0675,
    CVE-2020-0676, CVE-2020-0677, CVE-2020-0748,
    CVE-2020-0755, CVE-2020-0756)

  - An elevation of privilege vulnerability exists in
    Windows when the Windows kernel-mode driver fails to
    properly handle objects in memory. An attacker who
    successfully exploited this vulnerability could run
    arbitrary code in kernel mode. An attacker could then
    install programs; view, change, or delete data; or
    create new accounts with full user rights.
    (CVE-2020-0691)

  - An elevation of privilege vulnerability exists in the
    way that the Windows Function Discovery Service handles
    objects in memory. An attacker who successfully
    exploited the vulnerability could execute code with
    elevated permissions.  (CVE-2020-0680, CVE-2020-0682)

  - An elevation of privilege vulnerability exists in Active
    Directory Forest trusts due to a default setting that
    lets an attacker in the trusting forest request
    delegation of a TGT for an identity from the trusted
    forest.  (CVE-2020-0665)

  - An elevation of privilege vulnerability exists in
    Windows Error Reporting (WER) when WER handles and
    executes files. The vulnerability could allow elevation
    of privilege if an attacker can successfully exploit it.
    An attacker who successfully exploited the vulnerability
    could gain greater access to sensitive information and
    system functionality.  (CVE-2020-0753, CVE-2020-0754)

  - An information disclosure vulnerability exists when the
    Windows kernel improperly handles objects in memory. An
    attacker who successfully exploited this vulnerability
    could obtain information to further compromise the users
    system. An authenticated attacker could exploit this
    vulnerability by running a specially crafted
    application. The update addresses the vulnerability by
    correcting how the Windows kernel handles objects in
    memory. (CVE-2020-0736)

  - A remote code execution vulnerability exists in the way
    that Windows handles objects in memory. An attacker who
    successfully exploited the vulnerability could execute
    arbitrary code with elevated permissions on a target
    system.  (CVE-2020-0662)

  - An elevation of privilege vulnerability exists in the
    Windows Installer when MSI packages process symbolic
    links. An attacker who successfully exploited this
    vulnerability could bypass access restrictions to add or
    remove files.  (CVE-2020-0683, CVE-2020-0686)

  - An elevation of privilege vulnerability exists when the
    Windows Backup Service improperly handles file
    operations.  (CVE-2020-0703)

  - A remote code execution vulnerability exists in
    Microsoft Windows that could allow remote code execution
    if a .LNK file is processed. An attacker who
    successfully exploited this vulnerability could gain the
    same user rights as the local user.  (CVE-2020-0729)

  - An elevation of privilege vulnerability exists when the
    Windows Common Log File System (CLFS) driver improperly
    handles objects in memory. An attacker who successfully
    exploited this vulnerability could run processes in an
    elevated context.  (CVE-2020-0657)

  - An elevation of privilege vulnerability exists in
    Windows when the Win32k component fails to properly
    handle objects in memory. An attacker who successfully
    exploited this vulnerability could run arbitrary code in
    kernel mode. An attacker could then install programs;
    view, change, or delete data; or create new accounts
    with full user rights.  (CVE-2020-0719, CVE-2020-0720,
    CVE-2020-0721, CVE-2020-0722, CVE-2020-0723,
    CVE-2020-0724, CVE-2020-0725, CVE-2020-0726,
    CVE-2020-0731)

  - An elevation of privilege vulnerability exists when the
    Windows User Profile Service (ProfSvc) improperly
    handles symlinks. An attacker who successfully exploited
    this vulnerability could delete files and folders in an
    elevated context.  (CVE-2020-0730)

  - An information disclosure vulnerability exists when the
    Windows Network Driver Interface Specification (NDIS)
    improperly handles memory.  (CVE-2020-0705)

  - An information disclosure vulnerability exists in the
    way that the Windows Graphics Device Interface (GDI)
    handles objects in memory, allowing an attacker to
    retrieve information from a targeted system. By itself,
    the information disclosure does not allow arbitrary code
    execution; however, it could allow arbitrary code to be
    run if the attacker uses it in combination with another
    vulnerability.  (CVE-2020-0744)

  - A remote code execution vulnerability exists in Remote
    Desktop Services formerly known as Terminal Services
    when an authenticated attacker abuses clipboard
    redirection. An attacker who successfully exploited this
    vulnerability could execute arbitrary code on the victim
    system. An attacker could then install programs; view,
    change, or delete data; or create new accounts with full
    user rights.  (CVE-2020-0655)

  - An elevation of privilege vulnerability exists when
    Windows Error Reporting manager improperly handles hard
    links. An attacker who successfully exploited this
    vulnerability could overwrite a targeted file leading to
    an elevated status.  (CVE-2020-0678)

  - An elevation of privilege vulnerability exists in the
    way that the Windows Search Indexer handles objects in
    memory. An attacker who successfully exploited the
    vulnerability could execute code with elevated
    permissions.  (CVE-2020-0666, CVE-2020-0667,
    CVE-2020-0735, CVE-2020-0752)

  - An information disclosure vulnerability exists when the
    Telephony Service improperly discloses the contents of
    its memory. An attacker who successfully exploited the
    vulnerability could obtain information to further
    compromise a users system.  (CVE-2020-0698)

  - An elevation of privilege vulnerability exists when the
    Windows Graphics Component improperly handles objects in
    memory. An attacker who successfully exploited this
    vulnerability could run processes in an elevated
    context.  (CVE-2020-0715, CVE-2020-0745)

  - A remote code execution vulnerability exists in the way
    that the scripting engine handles objects in memory in
    Internet Explorer. The vulnerability could corrupt
    memory in such a way that an attacker could execute
    arbitrary code in the context of the current user. An
    attacker who successfully exploited the vulnerability
    could gain the same user rights as the current user.
    (CVE-2020-0673, CVE-2020-0674)

  - A remote code execution vulnerability exists when the
    Windows Imaging Library improperly handles memory.
    (CVE-2020-0708)");
  # https://support.microsoft.com/en-us/help/4537820/windows-7-update-kb4537820
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4d4017b3");
  # https://support.microsoft.com/en-us/help/4537813/windows-7-update-kb4537813
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?36196c17");
  script_set_attribute(attribute:"solution", value:
"Apply Security Only update KB4537813 or Cumulative Update KB4537820.

Please Note: These updates are only available through Microsoft's Extended Support Updates program.
This operating system is otherwise unsupported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-0738");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Service Tracing Privilege Elevation Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows_server_2008:r2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows_7");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

bulletin = "MS20-02";
kbs = make_list('4537820', '4537813');

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win7:'1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  smb_check_rollup(os:"6.1",
                   sp:1,
                   rollup_date:"02_2020",
                   bulletin:bulletin,
                   rollup_kb_list:[4537820, 4537813])
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

