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
  script_id(128642);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/17");

  script_cve_id(
    "CVE-2019-1142",
    "CVE-2019-1208",
    "CVE-2019-1214",
    "CVE-2019-1215",
    "CVE-2019-1216",
    "CVE-2019-1219",
    "CVE-2019-1220",
    "CVE-2019-1221",
    "CVE-2019-1235",
    "CVE-2019-1236",
    "CVE-2019-1240",
    "CVE-2019-1241",
    "CVE-2019-1242",
    "CVE-2019-1243",
    "CVE-2019-1244",
    "CVE-2019-1245",
    "CVE-2019-1246",
    "CVE-2019-1247",
    "CVE-2019-1248",
    "CVE-2019-1249",
    "CVE-2019-1250",
    "CVE-2019-1252",
    "CVE-2019-1256",
    "CVE-2019-1267",
    "CVE-2019-1268",
    "CVE-2019-1269",
    "CVE-2019-1271",
    "CVE-2019-1274",
    "CVE-2019-1280",
    "CVE-2019-1282",
    "CVE-2019-1285",
    "CVE-2019-1286",
    "CVE-2019-1287",
    "CVE-2019-1290",
    "CVE-2019-1291",
    "CVE-2019-1293"
  );
  script_xref(name:"MSKB", value:"4516064");
  script_xref(name:"MSKB", value:"4516067");
  script_xref(name:"MSFT", value:"MS19-4516064");
  script_xref(name:"MSFT", value:"MS19-4516067");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");

  script_name(english:"KB4516064: Windows 8.1 and Windows Server 2012 R2 September 2019 Security Update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security update 4516064
or cumulative update 4516067. It is, therefore, affected by
multiple vulnerabilities :

  - An elevation of privilege vulnerability exists in
    Windows Text Service Framework (TSF) when the TSF server
    process does not validate the source of input or
    commands it receives. An attacker who successfully
    exploited this vulnerability could inject commands or
    read input sent through a malicious Input Method Editor
    (IME). This only affects systems that have installed an
    IME.  (CVE-2019-1235)

  - An information disclosure exists in the Windows Common
    Log File System (CLFS) driver when it fails to properly
    handle sandbox checks. An attacker who successfully
    exploited this vulnerability could potentially read data
    outside their expected limits.  (CVE-2019-1282)

  - An information disclosure vulnerability exists when the
    Windows kernel fails to properly initialize a memory
    address. An attacker who successfully exploited this
    vulnerability could obtain information to further
    compromise the users system.  (CVE-2019-1274)

  - An elevation of privilege vulnerability exists when the
    .NET Framework common language runtime (CLR) allows file
    creation in arbitrary locations. An attacker who
    successfully exploited this vulnerability could write
    files to folders that require higher privileges than
    what the attacker already has.  (CVE-2019-1142)

  - A remote code execution vulnerability exists when the
    Windows Jet Database Engine improperly handles objects
    in memory. An attacker who successfully exploited this
    vulnerability could execute arbitrary code on a victim
    system. An attacker could exploit this vulnerability by
    enticing a victim to open a specially crafted file. The
    update addresses the vulnerability by correcting the way
    the Windows Jet Database Engine handles objects in
    memory. (CVE-2019-1240, CVE-2019-1241, CVE-2019-1242,
    CVE-2019-1243, CVE-2019-1246, CVE-2019-1247,
    CVE-2019-1248, CVE-2019-1249, CVE-2019-1250)

  - An elevation of privilege vulnerability exists in
    Microsoft Compatibility Appraiser where a configuration
    file, with local privileges, is vulnerable to symbolic
    link and hard link attacks. An attacker who successfully
    exploited this vulnerability could run processes in an
    elevated context. An attacker could then install
    programs; view, change or delete data.  (CVE-2019-1267)

  - A remote code execution vulnerability exists in
    Microsoft Windows that could allow remote code execution
    if a .LNK file is processed. An attacker who
    successfully exploited this vulnerability could gain the
    same user rights as the local user.  (CVE-2019-1280)

  - An information disclosure vulnerability exists in
    Windows when the Windows SMB Client kernel-mode driver
    fails to properly handle objects in memory. An attacker
    who successfully exploited the vulnerability could
    potentially disclose contents of System memory.
    (CVE-2019-1293)

  - An information disclosure vulnerability exists when
    DirectWrite improperly discloses the contents of its
    memory. An attacker who successfully exploited the
    vulnerability could obtain information to further
    compromise the users system. There are multiple ways an
    attacker could exploit the vulnerability, such as by
    convincing a user to open a specially crafted document,
    or by convincing a user to visit an untrusted webpage.
    The security update addresses the vulnerability by
    correcting how DirectWrite handles objects in memory.
    (CVE-2019-1244, CVE-2019-1245)

  - An elevation of privilege vulnerability exists in
    Windows when the Win32k component fails to properly
    handle objects in memory. An attacker who successfully
    exploited this vulnerability could run arbitrary code in
    kernel mode. An attacker could then install programs;
    view, change, or delete data; or create new accounts
    with full user rights.  (CVE-2019-1256, CVE-2019-1285)

  - A remote code execution vulnerability exists in the way
    that the VBScript engine handles objects in memory. The
    vulnerability could corrupt memory in such a way that an
    attacker could execute arbitrary code in the context of
    the current user. An attacker who successfully exploited
    the vulnerability could gain the same user rights as the
    current user.  (CVE-2019-1208, CVE-2019-1236)

  - An elevation of privilege vulnerability exists in the
    way that the Windows Network Connectivity Assistant
    handles objects in memory. An attacker who successfully
    exploited the vulnerability could execute code with
    elevated permissions.  (CVE-2019-1287)

  - A remote code execution vulnerability exists in the
    Windows Remote Desktop Client when a user connects to a
    malicious server. An attacker who successfully exploited
    this vulnerability could execute arbitrary code on the
    computer of the connecting client. An attacker could
    then install programs; view, change, or delete data; or
    create new accounts with full user rights.
    (CVE-2019-1290, CVE-2019-1291)

  - An elevation of privilege vulnerability exists when
    Windows improperly handles calls to Advanced Local
    Procedure Call (ALPC). An attacker who successfully
    exploited this vulnerability could run arbitrary code in
    the security context of the local system. An attacker
    could then install programs; view, change, or delete
    data; or create new accounts with full user rights.
    (CVE-2019-1269)

  - A security feature bypass vulnerability exists when
    Microsoft Browsers fail to validate the correct Security
    Zone of requests for specific URLs. This could allow an
    attacker to cause a user to access a URL in a less
    restricted Internet Security Zone than intended.
    (CVE-2019-1220)

  - An elevation of privilege exists when Winlogon does not
    properly handle file path information. An attacker who
    successfully exploited this vulnerability could run
    arbitrary code. An attacker could then install programs;
    view, change, or delete data; or create new accounts
    with full user rights.  (CVE-2019-1268)

  - An elevation of privilege vulnerability exists when the
    Windows Common Log File System (CLFS) driver improperly
    handles objects in memory. An attacker who successfully
    exploited this vulnerability could run processes in an
    elevated context.  (CVE-2019-1214)

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
    in memory. (CVE-2019-1252, CVE-2019-1286)

  - An information disclosure vulnerability exists when
    DirectX improperly handles objects in memory. An
    attacker who successfully exploited this vulnerability
    could obtain information to further compromise the users
    system. An authenticated attacker could exploit this
    vulnerability by running a specially crafted
    application. The update addresses the vulnerability by
    correcting how DirectX handles objects in memory.
    (CVE-2019-1216)

  - An elevation of privilege exists in hdAudio.sys which
    may lead to an out of band write. An attacker who
    successfully exploited this vulnerability could run
    processes in an elevated context. An attacker could then
    install programs; view, change or delete data.
    (CVE-2019-1271)

  - An information disclosure vulnerability exists when the
    Windows Transaction Manager improperly handles objects
    in memory. An attacker who successfully exploited this
    vulnerability could potentially read data that was not
    intended to be disclosed.  (CVE-2019-1219)

  - An elevation of privilege vulnerability exists in the
    way that ws2ifsl.sys (Winsock) handles objects in
    memory. An attacker who successfully exploited the
    vulnerability could execute code with elevated
    privileges.  (CVE-2019-1215)

  - A remote code execution vulnerability exists in the way
    that the scripting engine handles objects in memory in
    Internet Explorer. The vulnerability could corrupt
    memory in such a way that an attacker could execute
    arbitrary code in the context of the current user. An
    attacker who successfully exploited the vulnerability
    could gain the same user rights as the current user.
    (CVE-2019-1221)");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4516064/windows-8-1-kb4516064");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4516067/windows-8-1-kb4516067");
  script_set_attribute(attribute:"solution", value:
"Apply Security Only update KB4516064 or Cumulative Update KB4516067.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1291");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/10");

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

bulletin = "MS19-09";
kbs = make_list('4516067', '4516064');

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
                   rollup_date:"09_2019",
                   bulletin:bulletin,
                   rollup_kb_list:[4516067, 4516064])
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
