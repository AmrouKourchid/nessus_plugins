#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(204715);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/26");

  script_cve_id("CVE-2021-24112", "CVE-2024-21170");
  script_xref(name:"IAVA", value:"2024-A-0430-S");

  script_name(english:"Oracle MySQL Connectors (Jul 2024 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The 8.4.0 versions of MySQL Connectors installed on the remote host are affected by multiple vulnerabilities as
referenced in the July 2024 CPU advisory.

  - Vulnerability in the MySQL Connectors product of Oracle MySQL (component: Connector/Net (.NET Core)).
    Supported versions that are affected are 8.4.0 and prior. Difficult to exploit vulnerability allows
    unauthenticated attacker with network access via multiple protocols to compromise MySQL Connectors.
    Successful attacks of this vulnerability can result in takeover of MySQL Connectors. (CVE-2021-24112)

  - Vulnerability in the MySQL Connectors product of Oracle MySQL (component: Connector/Python). Supported
    versions that are affected are 8.4.0 and prior. Easily exploitable vulnerability allows low privileged
    attacker with network access via multiple protocols to compromise MySQL Connectors. Successful attacks of
    this vulnerability can result in unauthorized update, insert or delete access to some of MySQL Connectors
    accessible data as well as unauthorized read access to a subset of MySQL Connectors accessible data and
    unauthorized ability to cause a partial denial of service (partial DOS) of MySQL Connectors.
    (CVE-2024-21170)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpujul2024csaf.json");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujul2024.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2024 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-24112");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-21170");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:mysql_connectors");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mysql_connectors_version_nix.nbin", "mysql_connectors_version_win.nbin");
  script_require_keys("installed_sw/MySQL Connector");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'MySQL Connector');
var product = tolower(app_info['Product']);

vcf::check_granularity(app_info:app_info, sig_segments:3);

if ('net' >!< product && 'python' >!< product)
  audit(AUDIT_PACKAGE_NOT_AFFECTED, product);

var constraints = [
  {'min_version': '0.0', 'max_version' : '8.4.0', 'fixed_display' : '9.0.0'},
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
