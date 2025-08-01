#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156068);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/17");

  script_cve_id(
    "CVE-2021-41333",
    "CVE-2021-43207",
    "CVE-2021-43216",
    "CVE-2021-43217",
    "CVE-2021-43219",
    "CVE-2021-43222",
    "CVE-2021-43223",
    "CVE-2021-43224",
    "CVE-2021-43226",
    "CVE-2021-43227",
    "CVE-2021-43228",
    "CVE-2021-43229",
    "CVE-2021-43230",
    "CVE-2021-43231",
    "CVE-2021-43232",
    "CVE-2021-43233",
    "CVE-2021-43234",
    "CVE-2021-43235",
    "CVE-2021-43236",
    "CVE-2021-43237",
    "CVE-2021-43238",
    "CVE-2021-43239",
    "CVE-2021-43240",
    "CVE-2021-43246",
    "CVE-2021-43247",
    "CVE-2021-43248",
    "CVE-2021-43880",
    "CVE-2021-43883",
    "CVE-2021-43893"
  );
  script_xref(name:"MSKB", value:"5008215");
  script_xref(name:"MSFT", value:"MS21-5008215");
  script_xref(name:"IAVA", value:"2021-A-0586-S");
  script_xref(name:"IAVA", value:"2021-A-0582-S");

  script_name(english:"KB5008215: Windows 11 Security Update (December 2021)");

  script_set_attribute(attribute:"synopsis", value:
"The Windows 11 installation on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Windows 11 installation on the remote host is missing
security updates. It is, therefore, affected by multiple
vulnerabilities:

  - An elevation of privilege vulnerability. An attacker can
    exploit this to gain elevated privileges.
    (CVE-2021-41333, CVE-2021-43207, CVE-2021-43223,
    CVE-2021-43226, CVE-2021-43229, CVE-2021-43230,
    CVE-2021-43231, CVE-2021-43237, CVE-2021-43238,
    CVE-2021-43239, CVE-2021-43240, CVE-2021-43247,
    CVE-2021-43248, CVE-2021-43880, CVE-2021-43883,
    CVE-2021-43893)

  - An information disclosure vulnerability. An attacker can
    exploit this to disclose potentially sensitive
    information. (CVE-2021-43216, CVE-2021-43222,
    CVE-2021-43224, CVE-2021-43227, CVE-2021-43235,
    CVE-2021-43236)

  - A denial of service (DoS) vulnerability. An attacker can
    exploit this issue to cause the affected component to
    deny system or application services. (CVE-2021-43219,
    CVE-2021-43228)

  - A remote code execution vulnerability. An attacker can
    exploit this to bypass authentication and execute
    unauthorized arbitrary commands. (CVE-2021-43217,
    CVE-2021-43232, CVE-2021-43233, CVE-2021-43234)");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5008215");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released KB5008215 to address this issue.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-43217");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/12/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows_11_21h2");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_check_rollup.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}


include('smb_hotfixes_fcheck.inc');
include('smb_hotfixes.inc');
include('smb_func.inc');

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

bulletin = "MS21-12";
kbs = make_list('5008215');

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit('SMB/Registry/Enumerated');
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp_range(win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  smb_check_rollup(os:"10",
                   sp:0,
                   os_build:22000,
                   rollup_date:'12_2021',
                   bulletin:bulletin,
                   rollup_kb_list:[5008215])
                   
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
