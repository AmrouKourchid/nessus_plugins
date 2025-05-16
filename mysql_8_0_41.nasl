#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(214534);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/18");

  script_cve_id(
    "CVE-2021-37519",
    "CVE-2024-11053",
    "CVE-2025-21490",
    "CVE-2025-21491",
    "CVE-2025-21495",
    "CVE-2025-21497",
    "CVE-2025-21500",
    "CVE-2025-21501",
    "CVE-2025-21503",
    "CVE-2025-21505",
    "CVE-2025-21518",
    "CVE-2025-21519",
    "CVE-2025-21520",
    "CVE-2025-21522",
    "CVE-2025-21523",
    "CVE-2025-21529",
    "CVE-2025-21531",
    "CVE-2025-21540",
    "CVE-2025-21543",
    "CVE-2025-21546",
    "CVE-2025-21555",
    "CVE-2025-21559"
  );
  script_xref(name:"IAVA", value:"2025-A-0050");
  script_xref(name:"IAVA", value:"2025-A-0272");

  script_name(english:"Oracle MySQL Server 8.0.x < 8.0.41 (January 2025 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The versions of MySQL Server installed on the remote host are affected by multiple vulnerabilities as referenced in the
January 2025 CPU advisory.

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Parser).  Supported versions that are
    affected are 8.0.40 and prior, 8.4.3 and prior and  9.1.0 and prior. Easily exploitable vulnerability allows low
    privileged attacker with network access via multiple protocols to compromise MySQL Server.  Successful attacks of
    this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS)
    of MySQL Server. (CVE-2025-21522)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Optimizer).  Supported versions that
    are affected are 8.0.40 and prior, 8.4.3 and prior and  9.1.0 and prior. Easily exploitable vulnerability allows low
    privileged attacker with network access via multiple protocols to compromise MySQL Server.  Successful attacks of this
    vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of 
    MySQL Server. (CVE-2025-21518)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Optimizer).  Supported versions that
    are affected are 8.0.40 and prior, 8.4.3 and prior and  9.1.0 and prior. Easily exploitable vulnerability allows low
    privileged attacker with network access via multiple protocols to compromise MySQL Server.  Successful attacks of this
    vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of
    MySQL Server. (CVE-2025-21501)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujan2025.html");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpujan2025csaf.json");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2025 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:M/C:N/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-21559");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-37519");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/01/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/01/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/01/23");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:mysql");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mysql_version.nasl", "mysql_login.nasl", "mysql_version_local.nasl", "mysql_win_installed.nbin", "macosx_mysql_installed.nbin");
  script_require_keys("installed_sw/MySQL Server");

  exit(0);
}

include('vcf_extras_mysql.inc');

var app_info = vcf::mysql::combined_get_app_info();

vcf::check_all_backporting(app_info:app_info);

var constraints = [{ 'min_version' : '8.0', 'fixed_version' : '8.0.41'}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
