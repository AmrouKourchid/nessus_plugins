#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(187793);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/21");

  script_cve_id("CVE-2024-0056");
  script_xref(name:"MSKB", value:"5032968");
  script_xref(name:"MSKB", value:"5033592");
  script_xref(name:"MSFT", value:"MS24-5032968");
  script_xref(name:"MSFT", value:"MS24-5033592");
  script_xref(name:"IAVA", value:"2024-A-0014-S");

  script_name(english:"Security Updates for Microsoft SQL Server (January 2024) (Remote)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft SQL Server installation on the remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft SQL Server installation on the remote host is
missing a security update. It is, therefore, affected by the
following vulnerability:

  - A security feature bypass vulnerability exists. An
    attacker can exploit this and bypass the security
    feature and perform unauthorized actions compromising
    the integrity of the system/application. (CVE-2024-0056)");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5032968");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5033592");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released security updates for Microsoft SQL Server.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-0056");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/09");

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
  (ver_compare(ver:ver, minver:'16.0.1000.6',   fix: '16.0.1110.1') < 0) ||
  (ver_compare(ver:ver, minver:'16.0.4003.1',   fix: '16.0.4100.1') < 0)
)
{
  var report = '';
  if (!empty_or_null(version))  report += '\n  SQL Server Version   : ' + version;
  if (!empty_or_null(instance)) report += '\n  SQL Server Instance  : ' + instance;
  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
}
else audit(AUDIT_INST_VER_NOT_VULN, 'MSSQL', version);
