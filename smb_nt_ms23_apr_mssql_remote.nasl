#%NASL_MIN_LEVEL 80900
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
  script_id(175451);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/08/11");

  script_cve_id("CVE-2023-23384");
  script_xref(name:"MSKB", value:"5020863");
  script_xref(name:"MSKB", value:"5021037");
  script_xref(name:"MSKB", value:"5021045");
  script_xref(name:"MSKB", value:"5021112");
  script_xref(name:"MSKB", value:"5021123");
  script_xref(name:"MSKB", value:"5021124");
  script_xref(name:"MSKB", value:"5021125");
  script_xref(name:"MSKB", value:"5021126");
  script_xref(name:"MSKB", value:"5021127");
  script_xref(name:"MSKB", value:"5021128");
  script_xref(name:"MSKB", value:"5021129");
  script_xref(name:"MSKB", value:"5021522");
  script_xref(name:"MSFT", value:"MS23-5020863");
  script_xref(name:"MSFT", value:"MS23-5021037");
  script_xref(name:"MSFT", value:"MS23-5021045");
  script_xref(name:"MSFT", value:"MS23-5021112");
  script_xref(name:"MSFT", value:"MS23-5021123");
  script_xref(name:"MSFT", value:"MS23-5021124");
  script_xref(name:"MSFT", value:"MS23-5021125");
  script_xref(name:"MSFT", value:"MS23-5021126");
  script_xref(name:"MSFT", value:"MS23-5021127");
  script_xref(name:"MSFT", value:"MS23-5021128");
  script_xref(name:"MSFT", value:"MS23-5021129");
  script_xref(name:"MSFT", value:"MS23-5021522");
  script_xref(name:"IAVA", value:"2023-A-0189-S");

  script_name(english:"Security Updates for Microsoft SQL Server (April 2023)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft SQL Server installation on the remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft SQL Server installation on the remote host is
missing a security update. It is, therefore, affected by the
following vulnerability:

  - A remote code execution vulnerability. An attacker can
    exploit this to bypass authentication and execute
    unauthorized arbitrary commands. (CVE-2023-23384)
    
Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5020863");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5021037");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5021045");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5021112");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5021123");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5021124");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5021125");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5021126");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5021127");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5021128");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5021129");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5021522");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released security updates for Microsoft SQL Server.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-23384");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/12");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sql_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  (ver_compare(ver:ver, minver:'10.0.6000.29',  fix: '10.0.6814.4') < 0) ||
  (ver_compare(ver:ver, minver:'10.50.6000.34', fix: '10.50.6785.2') < 0) ||
  (ver_compare(ver:ver, minver:'11.0.7001.0',   fix: '11.0.7512.11') < 0) ||
  (ver_compare(ver:ver, minver:'12.0.6024.0',   fix: '12.0.6174.8') < 0) ||
  (ver_compare(ver:ver, minver:'12.0.6205.1',   fix: '12.0.6444.4') < 0) ||
  (ver_compare(ver:ver, minver:'13.0.6300.2',   fix: '13.0.6430.49') < 0) ||
  (ver_compare(ver:ver, minver:'13.0.7000.253', fix: '13.0.7024.30') < 0) ||
  (ver_compare(ver:ver, minver:'14.0.1000.169', fix: '14.0.2047.8') < 0) ||
  (ver_compare(ver:ver, minver:'14.0.3006.16',  fix: '14.0.3460.9') < 0) ||
  (ver_compare(ver:ver, minver:'15.0.2000.5',   fix: '15.0.2101.7') < 0) ||
  (ver_compare(ver:ver, minver:'15.0.4003.23',  fix: '15.0.4280.7') < 0) ||
  (ver_compare(ver:ver, minver:'16.0.1000.6',   fix: '16.0.1050.5') < 0)
)
{
  var report = '';
  if (!empty_or_null(version))  report += '\n  SQL Server Version   : ' + version;
  if (!empty_or_null(instance)) report += '\n  SQL Server Instance  : ' + instance;
  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
}
else audit(AUDIT_INST_VER_NOT_VULN, 'MSSQL', version);
