#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(125063);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/17");

  script_cve_id(
    "CVE-2018-12126",
    "CVE-2018-12127",
    "CVE-2018-12130",
    "CVE-2019-0708",
    "CVE-2019-0725",
    "CVE-2019-0734",
    "CVE-2019-0758",
    "CVE-2019-0820",
    "CVE-2019-0863",
    "CVE-2019-0864",
    "CVE-2019-0881",
    "CVE-2019-0882",
    "CVE-2019-0884",
    "CVE-2019-0885",
    "CVE-2019-0889",
    "CVE-2019-0890",
    "CVE-2019-0891",
    "CVE-2019-0893",
    "CVE-2019-0894",
    "CVE-2019-0895",
    "CVE-2019-0896",
    "CVE-2019-0897",
    "CVE-2019-0898",
    "CVE-2019-0899",
    "CVE-2019-0900",
    "CVE-2019-0901",
    "CVE-2019-0902",
    "CVE-2019-0903",
    "CVE-2019-0911",
    "CVE-2019-0918",
    "CVE-2019-0921",
    "CVE-2019-0930",
    "CVE-2019-0936",
    "CVE-2019-0940",
    "CVE-2019-0961",
    "CVE-2019-0980",
    "CVE-2019-0981",
    "CVE-2019-11091"
  );
  script_xref(name:"MSKB", value:"4499164");
  script_xref(name:"MSKB", value:"4499175");
  script_xref(name:"MSFT", value:"MS19-4499164");
  script_xref(name:"MSFT", value:"MS19-4499175");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/04/15");
  script_xref(name:"CEA-ID", value:"CEA-2020-0129");
  script_xref(name:"CEA-ID", value:"CEA-2019-0700");
  script_xref(name:"CEA-ID", value:"CEA-2019-0324");
  script_xref(name:"CEA-ID", value:"CEA-2019-0547");
  script_xref(name:"CEA-ID", value:"CEA-2019-0326");

  script_name(english:"KB4499175: Windows 7 and Windows Server 2008 R2 May 2019 Security Update (MDSUM/RIDL) (MFBDS/RIDL/ZombieLoad) (MLPDS/RIDL) (MSBDS/Fallout) (BlueKeep)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security update 4499175
or cumulative update 4499164. It is, therefore, affected by
multiple vulnerabilities :

  - A new subclass of speculative execution side channel vulnerabilities,
    known as Microarchitectural Data Sampling, exist in Windows.
    An attacker who successfully exploited these vulnerabilities 
    may be able to read privileged data across trust boundaries. 
    In shared resource environments (such as exists in some cloud 
    services configurations), these vulnerabilities could allow 
    one virtual machine to improperly access information from 
    another. In non-browsing scenarios on standalone systems, an 
    attacker would need prior access to the system or an ability 
    to run a specially crafted application on the target system 
    to leverage these vulnerabilities.
    (CVE-2018-12126, CVE-2018-12127, CVE-2018-12130, CVE-2019-11091)

  - A denial of service vulnerability exists when .NET
    Framework and .NET Core improperly process RegEx
    strings. An attacker who successfully exploited this
    vulnerability could cause a denial of service against a
    .NET application. A remote unauthenticated attacker
    could exploit this vulnerability by issuing specially
    crafted requests to a .NET Framework (or .NET core)
    application. The update addresses the vulnerability by
    correcting how .NET Framework and .NET Core applications
    handle RegEx string processing. (CVE-2019-0820)

  - A remote code execution vulnerability exists when
    Microsoft Windows OLE fails to properly validate user
    input. An attacker could exploit the vulnerability to
    execute malicious code.  (CVE-2019-0885)

  - An elevation of privilege vulnerability exists when the
    Windows Kernel improperly handles key enumeration. An
    attacker who successfully exploited the vulnerability
    could gain elevated privileges on a targeted system. A
    locally authenticated attacker could exploit this
    vulnerability by running a specially crafted
    application. The security update addresses the
    vulnerability by helping to ensure that the Windows
    Kernel properly handles key enumeration. (CVE-2019-0881)

  - An elevation of privilege vulnerability exists in
    Microsoft Windows when Windows fails to properly handle
    certain symbolic links. An attacker who successfully
    exploited this vulnerability could potentially set
    certain items to run at a higher level and thereby
    elevate permissions.  (CVE-2019-0936)

  - An spoofing vulnerability exists when Internet Explorer
    improperly handles URLs. An attacker who successfully
    exploited this vulnerability could trick a user by
    redirecting the user to a specially crafted website. The
    specially crafted website could either spoof content or
    serve as a pivot to chain an attack with other
    vulnerabilities in web services.  (CVE-2019-0921)

  - A remote code execution vulnerability exists in the way
    that Microsoft browsers access objects in memory. The
    vulnerability could corrupt memory in a way that could
    allow an attacker to execute arbitrary code in the
    context of the current user. An attacker who
    successfully exploited the vulnerability could gain the
    same user rights as the current user.  (CVE-2019-0940)

  - A remote code execution vulnerability exists in the way
    the scripting engine handles objects in memory in
    Microsoft browsers. The vulnerability could corrupt
    memory in such a way that an attacker could execute
    arbitrary code in the context of the current user. An
    attacker who successfully exploited the vulnerability
    could gain the same user rights as the current user.
    (CVE-2019-0884, CVE-2019-0911, CVE-2019-0918)

  - A remote code execution vulnerability exists when the
    Windows Jet Database Engine improperly handles objects
    in memory. An attacker who successfully exploited this
    vulnerability could execute arbitrary code on a victim
    system. An attacker could exploit this vulnerability by
    enticing a victim to open a specially crafted file. The
    update addresses the vulnerability by correcting the way
    the Windows Jet Database Engine handles objects in
    memory. (CVE-2019-0889, CVE-2019-0890, CVE-2019-0891,
    CVE-2019-0893, CVE-2019-0894, CVE-2019-0895,
    CVE-2019-0896, CVE-2019-0897, CVE-2019-0898,
    CVE-2019-0899, CVE-2019-0900, CVE-2019-0901,
    CVE-2019-0902)

  - A memory corruption vulnerability exists in the Windows
    Server DHCP service when processing specially crafted
    packets. An attacker who successfully exploited the
    vulnerability could run arbitrary code on the DHCP
    server.  (CVE-2019-0725)

  - A denial of service vulnerability exists when .NET
    Framework improperly handles objects in heap memory. An
    attacker who successfully exploited this vulnerability
    could cause a denial of service against a .NET
    application.  (CVE-2019-0864)

  - A remote code execution vulnerability exists in Remote
    Desktop Services formerly known as Terminal Services
    when an unauthenticated attacker connects to the target
    system using RDP and sends specially crafted requests.
    This vulnerability is pre-authentication and requires no
    user interaction. An attacker who successfully exploited
    this vulnerability could execute arbitrary code on the
    target system. An attacker could then install programs;
    view, change, or delete data; or create new accounts
    with full user rights.  (CVE-2019-0708)

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
    in memory. (CVE-2019-0758, CVE-2019-0882, CVE-2019-0961)

  - An information disclosure vulnerability exists when
    Internet Explorer improperly handles objects in memory.
    An attacker who successfully exploited the vulnerability
    could obtain information to further compromise the users
    system.  (CVE-2019-0930)

  - An elevation of privilege vulnerability exists in
    Microsoft Windows when a man-in-the-middle attacker is
    able to successfully decode and replace authentication
    request using Kerberos, allowing an attacker to be
    validated as an Administrator. The update addresses this
    vulnerability by changing how these requests are
    validated. (CVE-2019-0734)

  - An elevation of privilege vulnerability exists in the
    way Windows Error Reporting (WER) handles files. An
    attacker who successfully exploited this vulnerability
    could run arbitrary code in kernel mode. An attacker
    could then install programs; view, change, or delete
    data; or create new accounts with administrator
    privileges.  (CVE-2019-0863)

  - A denial of service vulnerability exists when .NET
    Framework or .NET Core improperly handle web requests.
    An attacker who successfully exploited this
    vulnerability could cause a denial of service against a
    .NET Framework or .NET Core web application. The
    vulnerability can be exploited remotely, without
    authentication. A remote unauthenticated attacker could
    exploit this vulnerability by issuing specially crafted
    requests to the .NET Framework or .NET Core application.
    The update addresses the vulnerability by correcting how
    .NET Framework or .NET Core web applications handles web
    requests. (CVE-2019-0980, CVE-2019-0981)

  - A remote code execution vulnerability exists in the way
    that the Windows Graphics Device Interface (GDI) handles
    objects in the memory. An attacker who successfully
    exploited this vulnerability could take control of the
    affected system. An attacker could then install
    programs; view, change, or delete data; or create new
    accounts with full user rights.  (CVE-2019-0903)");
  # https://support.microsoft.com/en-us/help/4499164/windows-7-update-kb4499164
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?283578f0");
  # https://support.microsoft.com/en-us/help/4499175/windows-7-update-kb4499175
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0eea1c91");
  # https://support.microsoft.com/en-us/help/4072698/windows-server-speculative-execution-side-channel-vulnerabilities-prot
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8902cebb");
  # https://community.tenable.com/s/article/Speculative-Execution-Side-Channel-Vulnerability-Plugin-and-Mitigation-Information
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7b2b84b8");
  script_set_attribute(attribute:"solution", value:
"Apply Security Only update KB4499175 or Cumulative Update KB4499164.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0708");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-0725");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'CVE-2019-0708 BlueKeep RDP Remote Windows Kernel Use After Free');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows_server_2008:r2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows_7");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_check_rollup.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl", "microsoft_windows_env_vars.nasl");
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

bulletin = "MS19-05";
kbs = make_list('4499164', '4499175');

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);
productname = get_kb_item_or_exit("SMB/ProductName");

if (hotfix_check_sp_range(win7:'1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  smb_check_rollup(os:"6.1",
                   sp:1,
                   rollup_date:"05_2019",
                   bulletin:bulletin,
                   rollup_kb_list:[4499164, 4499175])
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
