#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#

include('compat.inc');

if (description)
{
  script_id(183297);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/07");

  script_cve_id("CVE-2023-30535");

  script_name(english:"Oracle GoldenGate for Big Data RCE (October 2023 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The Oracle GoldenGate for Big Data application on the remote host is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Oracle GoldenGate for Big Data application located on the remote
host is 21.3 <= 21.10. It is, therefore, affected by a remote code execution vulnerability: 

  - Vulnerability in the GoldenGate Big Data product of Oracle GoldenGate (component: Application Adapters (Snowflake JDBC)). 
    Supported versions that are affected are 21.3-21.10. Easily exploitable vulnerability allows high privileged attacker with 
    network access via HTTP to compromise GoldenGate Big Data. Successful attacks require human interaction from a person other 
    than the attacker. Successful attacks of this vulnerability can result in takeover of GoldenGate Big Data. (CVE-2023-30535)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.oracle.com/docs/tech/security-alerts/cpuoct2023cvrf.xml%20
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?11fda075");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuoct2023.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle GoldenGate for Big Data version 21.20 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-30535");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:goldengate_application_adapters");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"asset_categories", value:"component");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_goldengate_for_big_data_installed.nbin");
  script_require_keys("installed_sw/Oracle GoldenGate for Big Data");

  exit(0);
}

include('vcf.inc');

var app_name = 'Oracle GoldenGate for Big Data';
var app_info = vcf::get_app_info(app:app_name);

var constraints = [
  { 'min_version':'21.3.0.0.0', 'fixed_version':'21.11.0.0.0' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);