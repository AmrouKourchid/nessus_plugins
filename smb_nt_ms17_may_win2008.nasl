#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(100063);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/18");

  script_cve_id(
    "CVE-2017-0077",
    "CVE-2017-0171",
    "CVE-2017-0175",
    "CVE-2017-0190",
    "CVE-2017-0213",
    "CVE-2017-0214",
    "CVE-2017-0220",
    "CVE-2017-0242",
    "CVE-2017-0244",
    "CVE-2017-0245",
    "CVE-2017-0246",
    "CVE-2017-0258",
    "CVE-2017-0263",
    "CVE-2017-0267",
    "CVE-2017-0268",
    "CVE-2017-0269",
    "CVE-2017-0270",
    "CVE-2017-0271",
    "CVE-2017-0272",
    "CVE-2017-0273",
    "CVE-2017-0274",
    "CVE-2017-0275",
    "CVE-2017-0276",
    "CVE-2017-0277",
    "CVE-2017-0278",
    "CVE-2017-0279",
    "CVE-2017-0280",
    "CVE-2017-8552"
  );
  script_bugtraq_id(
    98097,
    98102,
    98103,
    98108,
    98109,
    98110,
    98111,
    98112,
    98114,
    98115,
    98258,
    98259,
    98260,
    98261,
    98263,
    98264,
    98265,
    98266,
    98267,
    98268,
    98270,
    98271,
    98272,
    98273,
    98274,
    98275,
    98298
  );
  script_xref(name:"MSKB", value:"4018196");
  script_xref(name:"MSKB", value:"4018466");
  script_xref(name:"MSKB", value:"4018556");
  script_xref(name:"MSKB", value:"4018821");
  script_xref(name:"MSKB", value:"4018885");
  script_xref(name:"MSKB", value:"4018927");
  script_xref(name:"MSKB", value:"4019149");
  script_xref(name:"MSKB", value:"4019204");
  script_xref(name:"MSKB", value:"4019206");
  script_xref(name:"MSFT", value:"MS17-4018196");
  script_xref(name:"MSFT", value:"MS17-4018466");
  script_xref(name:"MSFT", value:"MS17-4018556");
  script_xref(name:"MSFT", value:"MS17-4018821");
  script_xref(name:"MSFT", value:"MS17-4018885");
  script_xref(name:"MSFT", value:"MS17-4018927");
  script_xref(name:"MSFT", value:"MS17-4019149");
  script_xref(name:"MSFT", value:"MS17-4019204");
  script_xref(name:"MSFT", value:"MS17-4019206");
  script_xref(name:"IAVA", value:"2017-A-0148");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/08/10");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/04/18");

  script_name(english:"Windows 2008 May 2017 Multiple Security Updates");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing multiple security updates released
on 2017/05/09. It is, therefore, affected by multiple
vulnerabilities :

  - An elevation of privilege vulnerability exists when the
    Windows improperly handles objects in memory.
    (CVE-2017-0077)

  - A denial of service vulnerability exists in Windows DNS
    Server if the server is configured to answer version
    queries. An attacker who successfully exploited this
    vulnerability could cause the DNS Server service to
    become nonresponsive. (CVE-2017-0171)

   - An information disclosure vulnerability exists in the
    way that the Windows Graphics Device Interface+ (GDI+)
    handles objects in memory, allowing an attacker to
    retrieve information from a targeted system.
    (CVE-2017-0190)

  - An elevation of privilege vulnerability exists in the
    Windows COM Aggregate Marshaler due to an unspecified
    flaw. A local attacker can exploit this, via a specially
    crafted application, to execute arbitrary code with
    elevated privileges. (CVE-2017-0213)

  - An elevation of privilege vulnerability exists in
    Windows due to improper validation of user-supplied
    input when loading type libraries. A local attacker can
    exploit this, via a specially crafted application, to
    gain elevated privileges. (CVE-2017-0214)

  - An information disclosure vulnerability exists in the
    Windows kernel due to improper handling of objects in
    memory. A local attacker can exploit this, via a
    specially crafted application, to disclose sensitive
    information. (CVE-2017-0175, CVE-2017-0220)

  - An information disclosure vulnerability exists in the
    way some ActiveX objects are instantiated. An attacker
    who successfully exploited this vulnerability could gain
    access to protected memory contents.  (CVE-2017-0242)

  - An elevation of privilege vulnerability exists in the
    way that the Windows Kernel handles objects in memory.
    An attacker who successfully exploited the vulnerability
    could execute code with elevated permissions. On systems
    with Windows 7 for x64-based Systems or later installed,
    this vulnerability can lead to denial of service.
    (CVE-2017-0244)

  - An information disclosure vulnerability exists when the
    win32k component improperly provides kernel information.
    An attacker who successfully exploited the vulnerability
    could obtain information to further compromise the users
    system.  (CVE-2017-0245)

  - An elevation of privilege vulnerability exists when
    Windows improperly handles objects in memory. An
    attacker who successfully exploited this vulnerability
    could run processes in an elevated context. On computers
    with Windows 7 for x64-based systems or later installed,
    this vulnerability can lead to denial of service.
    (CVE-2017-0246)

  - An information disclosure vulnerability exists when the
    Windows kernel improperly initializes objects in memory.
    (CVE-2017-0258)

  - An elevation of privilege vulnerability exists in
    Windows when the Windows kernel-mode driver fails to
    properly handle objects in memory.
    (CVE-2017-0263)

  - An information disclosure vulnerability exists in the
    Microsoft Server Message Block 1.0 (SMBv1) server when
    handling certain requests. An unauthenticated, remote
    attacker can exploit this, via a specially crafted
    packet, to disclose sensitive information.
    (CVE-2017-0267)

  - An information disclosure vulnerability exists in the
    Microsoft Server Message Block 1.0 (SMBv1) server when
    handling certain requests. An unauthenticated, remote
    attacker can exploit this, via a specially crafted
    packet, to disclose sensitive information.
    (CVE-2017-0268)

  - A denial of service vulnerability exists in Microsoft
    Server Message Block (SMB) when handling a specially
    crafted request to the server. An unauthenticated,
    remote attacker can exploit this, via a crafted SMB
    request, to cause the system to stop responding.
    (CVE-2017-0269)

  - An information disclosure vulnerability exists in the
    Microsoft Server Message Block 1.0 (SMBv1) server when
    handling certain requests. An unauthenticated, remote
    attacker can exploit this, via a specially crafted
    packet, to disclose sensitive information.
    (CVE-2017-0270)

  - An information disclosure vulnerability exists in the
    Microsoft Server Message Block 1.0 (SMBv1) server when
    handling certain requests. An unauthenticated, remote
    attacker can exploit this, via a specially crafted
    packet, to disclose sensitive information.
    (CVE-2017-0271)

  - A remote code execution vulnerability exists in the
    Microsoft Server Message Block 1.0 (SMBv1) server when
    handling certain requests. An unauthenticated, remote
    attacker can exploit this, via a specially crafted
    packet, to execute arbitrary code on a target server.
    (CVE-2017-0272)

  - A denial of service vulnerability exists in Microsoft
    Server Message Block (SMB) when handling a specially
    crafted request to the server. An unauthenticated,
    remote attacker can exploit this, via a crafted SMB
    request, to cause the system to stop responding.
    (CVE-2017-0273)

  - An information disclosure vulnerability exists in the
    Microsoft Server Message Block 1.0 (SMBv1) server when
    handling certain requests. An unauthenticated, remote
    attacker can exploit this, via a specially crafted
    packet, to disclose sensitive information.
    (CVE-2017-0274)

  - An information disclosure vulnerability exists in the
    Microsoft Server Message Block 1.0 (SMBv1) server when
    handling certain requests. An unauthenticated, remote
    attacker can exploit this, via a specially crafted
    packet, to disclose sensitive information.
    (CVE-2017-0275)

  - An information disclosure vulnerability exists in the
    Microsoft Server Message Block 1.0 (SMBv1) server when
    handling certain requests. An unauthenticated, remote
    attacker can exploit this, via a specially crafted
    packet, to disclose sensitive information.
    (CVE-2017-0276)

  - A remote code execution vulnerability exists in the
    Microsoft Server Message Block 1.0 (SMBv1) server when
    handling certain requests. An unauthenticated, remote
    attacker can exploit this, via a specially crafted
    packet, to execute arbitrary code on a target server.
    (CVE-2017-0277)

  - A remote code execution vulnerability exists in the
    Microsoft Server Message Block 1.0 (SMBv1) server when
    handling certain requests. An unauthenticated, remote
    attacker can exploit this, via a specially crafted
    packet, to execute arbitrary code on a target server.
    (CVE-2017-0278)

  - A remote code execution vulnerability exists in the
    Microsoft Server Message Block 1.0 (SMBv1) server when
    handling certain requests. An unauthenticated, remote
    attacker can exploit this, via a specially crafted
    packet, to execute arbitrary code on a target server.
    (CVE-2017-0279)

  - A denial of service vulnerability exists in Microsoft
    Server Message Block (SMB) when handling a specially
    crafted request to the server. An unauthenticated,
    remote attacker can exploit this, via a crafted SMB
    request, to cause the system to stop responding.
    (CVE-2017-0280)

  - An information disclosure vulnerability exists in the
    GDI component due to improper handling of objects in
    memory. An unauthenticated, remote attacker can exploit
    this, by convincing a user to open a specially crafted
    document or visit a specially crafted website, to
    disclose the contents of memory. (CVE-2017-8552)");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4018196/title");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4018466/title");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4018556/title");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4018821/title");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4018885/title");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4018927/title");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4019149/title");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4019204/title");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4019206/title");
  script_set_attribute(attribute:"solution", value:
"Apply the following security updates :

  - KB4018196
  - KB4018466
  - KB4018556
  - KB4018821
  - KB4018885
  - KB4018927
  - KB4019149
  - KB4019204
  - KB4019206");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-0272");
  script_set_attribute(attribute: "cvss3_score_source", value: "manual");
  script_set_attribute(attribute:"cvss3_score_rationale", value:"Scoring adjustsed to align with CVSS 3.1 attack complexity guidance.");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows_server_2008");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS17-05';

kbs = make_list(
  "4018196", 
  "4018466",
  "4018556",
  "4018821",
  "4018885",
  "4018927",
  "4019149",
  "4019204",
  "4019206"
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

# KB4018196 Applies only to hosts having 'DNS Server' role installed
registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
dns_role_installed = get_registry_value(
  handle:hklm,
  item:"SYSTEM\CurrentControlSet\Services\DNS\DisplayName"
);
RegCloseKey(handle:hklm);
close_registry(close:TRUE);

# KBs only apply to Windows 2008
if (hotfix_check_sp_range(vista:'2') <= 0)
  audit(AUDIT_OS_SP_NOT_VULN);

productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ("Vista" >< productname) audit(AUDIT_OS_SP_NOT_VULN);

systemroot = hotfix_get_systemroot();
if (!systemroot) audit(AUDIT_PATH_NOT_DETERMINED, 'system root');

port   = kb_smb_transport();
login  = kb_smb_login();
pass   = kb_smb_password();
domain = kb_smb_domain();


if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

winsxs = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:"\1\WinSxS", string:systemroot);
winsxs_share = hotfix_path2share(path:systemroot);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:winsxs_share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, winsxs_share);
}

the_session = make_array(
  'login',    login,
  'password', pass,
  'domain',   domain,
  'share',    winsxs_share
);

vuln = 0;

# 4018196
if (!isnull(dns_role_installed))
{
  files = list_dir(basedir:winsxs, level:0, dir_pat:"dns-server-service_31bf3856ad364e35_", file_pat:"^dns\.exe$", max_recurse:1);
  vuln += hotfix_check_winsxs(os:'6.0',
                             sp:2,
                             files:files,
                             versions:make_list('6.0.6002.19765','6.0.6002.24089'),
                             max_versions:make_list('6.0.6002.20000','6.0.6003.99999'),
                             bulletin:bulletin,
                             kb:"4018196", session:the_session);
}

# 4018466
files = list_dir(basedir:winsxs, level:0, dir_pat:"smbserver-common_31bf3856ad364e35_", file_pat:"^srvnet\.sys$", max_recurse:1);
vuln += hotfix_check_winsxs(os:'6.0',
                            sp:2,
                            files:files,
                            versions:make_list('6.0.6002.19673','6.0.6002.24089'),
                            max_versions:make_list('6.0.6002.20000','6.0.6003.99999'),
                            bulletin:bulletin,
                            kb:"4018466", session:the_session);

# 4018556
files = list_dir(basedir:winsxs, level:0, dir_pat:"com-base-qfe-ole32_31bf3856ad364e35_", file_pat:"^ole32\.dll$", max_recurse:1);
vuln += hotfix_check_winsxs(os:'6.0',
                            sp:2,
                            files:files,
                            versions:make_list('6.0.6002.19773','6.0.6002.24089'),
                            max_versions:make_list('6.0.6002.20000','6.0.6003.99999'),
                            bulletin:bulletin,
                            kb:"4018556", session:the_session);

# 4018821
files = list_dir(basedir:winsxs, level:0, dir_pat:"tdi-over-tcpip_31bf3856ad364e35_", file_pat:"^tdx\.sys$", max_recurse:1);
vuln += hotfix_check_winsxs(os:'6.0',
                            sp:2,
                            files:files,
                            versions:make_list('6.0.6002.19762','6.0.6002.24087'),
                            max_versions:make_list('6.0.6002.20000','6.0.6003.99999'),
                            bulletin:bulletin,
                            kb:"4018821", session:the_session);

# 4018885
files = list_dir(basedir:winsxs, level:0, dir_pat:"tcpip-binaries_31bf3856ad364e35_", file_pat:"^tcpip\.sys$", max_recurse:1);
vuln += hotfix_check_winsxs(os:'6.0',
                            sp:2,
                            files:files,
                            versions:make_list('6.0.6002.19763','6.0.6002.24087'),
                            max_versions:make_list('6.0.6002.20000','6.0.6003.99999'),
                            bulletin:bulletin,
                            kb:"4018885", session:the_session);

# 4018927
files = list_dir(basedir:winsxs, level:0, dir_pat:"rds-datafactory-dll_31bf3856ad364e35_", file_pat:"^msadcf\.dll$", max_recurse:1);
vuln += hotfix_check_winsxs(os:'6.0',
                            sp:2,
                            files:files,
                            versions:make_list('6.0.6002.19770','6.0.6002.24089'),
                            max_versions:make_list('6.0.6002.20000','6.0.6003.99999'),
                            bulletin:bulletin,
                            kb:"4018927", session:the_session);

# 4019149
files = list_dir(basedir:winsxs, level:0, dir_pat:"lddmcore_31bf3856ad364e35_", file_pat:"^dxgkrnl\.sys$", max_recurse:1);
vuln += hotfix_check_winsxs(os:'6.0',
                            sp:2,
                            files:files,
                            versions:make_list('7.0.6002.19765','7.0.6002.24089'),
                            max_versions:make_list('7.0.6002.20000','7.0.6002.99999'),
                            bulletin:bulletin,
                            kb:"4019149", session:the_session);

# 4019204
files = list_dir(basedir:winsxs, level:0, dir_pat:"win32k_31bf3856ad364e35_", file_pat:"^win32k\.sys$", max_recurse:1);
vuln += hotfix_check_winsxs(os:'6.0',
                            sp:2,
                            files:files,
                            versions:make_list('6.0.6002.19778','6.0.6002.24095'),
                            max_versions:make_list('6.0.6002.20000','6.0.6003.99999'),
                            bulletin:bulletin,
                            kb:"4019204", session:the_session);

# 4019206
files = list_dir(basedir:winsxs, level:0, dir_pat:"gdi32_31bf3856ad364e35_", file_pat:"^gdi32\.dll$", max_recurse:1);
vuln += hotfix_check_winsxs(os:'6.0',
                            sp:2,
                            files:files,
                            versions:make_list('6.0.6002.19765','6.0.6002.24089'),
                            max_versions:make_list('6.0.6002.20000','6.0.6003.99999'),
                            bulletin:bulletin,
                            kb:"4019206", session:the_session);

if (vuln > 0)
{
  replace_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
