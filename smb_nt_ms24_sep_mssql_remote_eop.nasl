#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(207068);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/08");

  script_cve_id("CVE-2024-37341", "CVE-2024-37965", "CVE-2024-37980");
  script_xref(name:"MSKB", value:"5042207");
  script_xref(name:"MSKB", value:"5042209");
  script_xref(name:"MSKB", value:"5042578");
  script_xref(name:"MSKB", value:"5042749");
  script_xref(name:"MSKB", value:"5042211");
  script_xref(name:"MSKB", value:"5042215");
  script_xref(name:"MSKB", value:"5042214");
  script_xref(name:"MSKB", value:"5042217");
  script_xref(name:"MSFT", value:"MS24-5042207");
  script_xref(name:"MSFT", value:"MS24-5042209");
  script_xref(name:"MSFT", value:"MS24-5042578");
  script_xref(name:"MSFT", value:"MS24-5042749");
  script_xref(name:"MSFT", value:"MS24-5042211");
  script_xref(name:"MSFT", value:"MS24-5042215");
  script_xref(name:"MSFT", value:"MS24-5042214");
  script_xref(name:"MSFT", value:"MS24-5042217");
  script_xref(name:"IAVA", value:"2024-A-0565-S");

  script_name(english:"Security Updates for Microsoft SQL Server Elevation of Privilege (September 2024) (Remote)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft SQL Server installation on the remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft SQL Server installation on the remote host is missing a security update. It is, therefore, 
affected by the following vulnerabilities:

  - An elevation of privilege vulnerability. An authenticated, remote attacker can exploit this issue, to 
    gain elevated privileges. (CVE-2024-37341, CVE-2024-37965, CVE-2024-37980)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5042207");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5042209");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5042578");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5042749");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5042211");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5042215");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5042214");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5042217");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released security updates for Microsoft SQL Server.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-37980");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/09/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/12");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sql_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

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
  (ver_compare(ver:ver, minver:'13.0.6300.2',   fix: '13.0.6445.1') < 0) ||
  (ver_compare(ver:ver, minver:'13.0.7000.253', fix: '13.0.7040.1') < 0) ||
  (ver_compare(ver:ver, minver:'14.0.1000.169', fix: '14.0.2060.1') < 0) ||
  (ver_compare(ver:ver, minver:'14.0.3006.16',  fix: '14.0.3475.1') < 0) ||
  (ver_compare(ver:ver, minver:'15.0.2000.5',   fix: '15.0.2120.1') < 0) ||
  (ver_compare(ver:ver, minver:'15.0.4003.23',  fix: '15.0.4390.2') < 0) ||
  (ver_compare(ver:ver, minver:'16.0.1000.6',   fix: '16.0.1125.1') < 0) ||
  (ver_compare(ver:ver, minver:'16.0.4003.1',   fix: '16.0.4140.3') < 0)
)
{
  var report = '';
  if (!empty_or_null(version))  report += '\n  SQL Server Version   : ' + version;
  if (!empty_or_null(instance)) report += '\n  SQL Server Instance  : ' + instance;
  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
}
else audit(AUDIT_INST_VER_NOT_VULN, 'MSSQL', version);
