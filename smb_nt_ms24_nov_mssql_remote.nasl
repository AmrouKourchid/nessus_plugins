#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(211471);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/21");

  script_cve_id(
    "CVE-2024-38255",
    "CVE-2024-43459",
    "CVE-2024-43462",
    "CVE-2024-48993",
    "CVE-2024-48994",
    "CVE-2024-48995",
    "CVE-2024-48996",
    "CVE-2024-48997",
    "CVE-2024-48998",
    "CVE-2024-48999",
    "CVE-2024-49000",
    "CVE-2024-49001",
    "CVE-2024-49002",
    "CVE-2024-49003",
    "CVE-2024-49004",
    "CVE-2024-49005",
    "CVE-2024-49006",
    "CVE-2024-49007",
    "CVE-2024-49008",
    "CVE-2024-49009",
    "CVE-2024-49010",
    "CVE-2024-49011",
    "CVE-2024-49012",
    "CVE-2024-49013",
    "CVE-2024-49014",
    "CVE-2024-49015",
    "CVE-2024-49016",
    "CVE-2024-49017",
    "CVE-2024-49018",
    "CVE-2024-49021",
    "CVE-2024-49043"
  );
  script_xref(name:"MSKB", value:"5046855");
  script_xref(name:"MSKB", value:"5046856");
  script_xref(name:"MSKB", value:"5046857");
  script_xref(name:"MSKB", value:"5046858");
  script_xref(name:"MSKB", value:"5046859");
  script_xref(name:"MSKB", value:"5046860");
  script_xref(name:"MSKB", value:"5046861");
  script_xref(name:"MSKB", value:"5046862");
  script_xref(name:"MSFT", value:"MS24-5046855");
  script_xref(name:"MSFT", value:"MS24-5046856");
  script_xref(name:"MSFT", value:"MS24-5046857");
  script_xref(name:"MSFT", value:"MS24-5046858");
  script_xref(name:"MSFT", value:"MS24-5046859");
  script_xref(name:"MSFT", value:"MS24-5046860");
  script_xref(name:"MSFT", value:"MS24-5046861");
  script_xref(name:"MSFT", value:"MS24-5046862");
  script_xref(name:"IAVA", value:"2024-A-0731");

  script_name(english:"Security Updates for Microsoft SQL Server (September 2024) (Remote)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft SQL Server installation on the remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft SQL Server installation on the remote host is
missing security updates. It is, therefore, affected by
multiple vulnerabilities:

  - A remote code execution vulnerability. An attacker can
    exploit this to bypass authentication and execute
    unauthorized arbitrary commands. (CVE-2024-38255,
    CVE-2024-43459, CVE-2024-43462, CVE-2024-48993,
    CVE-2024-48994, CVE-2024-48995, CVE-2024-48996,
    CVE-2024-48997, CVE-2024-48998, CVE-2024-48999,
    CVE-2024-49000, CVE-2024-49001, CVE-2024-49002,
    CVE-2024-49003, CVE-2024-49004, CVE-2024-49005,
    CVE-2024-49006, CVE-2024-49007, CVE-2024-49008,
    CVE-2024-49009, CVE-2024-49010, CVE-2024-49011,
    CVE-2024-49012, CVE-2024-49013, CVE-2024-49014,
    CVE-2024-49015, CVE-2024-49016, CVE-2024-49017,
    CVE-2024-49018, CVE-2024-49021, CVE-2024-49043)");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5046855");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5046856");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5046857");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5046858");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5046859");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5046860");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5046861");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5046862");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released security updates for Microsoft SQL Server.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-49018");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/11/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/11/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/15");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sql_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mssqlserver_detect.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports(139, 445, 1433, "Services/mssql");

  exit(0);
}

var port = get_service(svc:'mssql', exit_on_fail:TRUE);
var instance = get_kb_item('MSSQL/' + port + '/InstanceName');
var version = get_kb_item_or_exit('MSSQL/' + port + '/Version');

# SQL Server checks are already paranoid, but we also can't check for Linux container SQL Server specifically
if (report_paranoia < 2) audit(AUDIT_PARANOID);

var ver = pregmatch(pattern:"^([0-9.]+)([^0-9]|$)", string:version);
if (!isnull(ver) && !isnull(ver[1])) ver = ver[1];

if (
  (ver_compare(ver:ver, minver:'13.0.6455.2', fix: '13.0.6455.2') < 0) ||
  (ver_compare(ver:ver, minver:'13.0.7000.253', fix: '13.0.7050.2 ') < 0) ||
  (ver_compare(ver:ver, minver:'14.0.1000.169', fix: '14.0.2070.1') < 0) ||
  (ver_compare(ver:ver, minver:'14.0.3006.16',  fix: '14.0.3485.1') < 0) ||
  (ver_compare(ver:ver, minver:'15.0.2000.5',   fix: '15.0.2130.3') < 0) ||
  (ver_compare(ver:ver, minver:'15.0.4003.23',  fix: '15.0.4410.1') < 0) ||
  (ver_compare(ver:ver, minver:'16.0.1000.6',   fix: '16.0.1135.2') < 0) ||
  (ver_compare(ver:ver, minver:'16.0.4003.1',   fix: '16.0.4155.4') < 0)
)
{
  var report = '';
  if (!empty_or_null(version))  report += '\n  SQL Server Version   : ' + version;
  if (!empty_or_null(instance)) report += '\n  SQL Server Instance  : ' + instance;
  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
}
else audit(AUDIT_INST_VER_NOT_VULN, 'MSSQL', version);
