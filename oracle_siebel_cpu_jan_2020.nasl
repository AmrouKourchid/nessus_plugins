#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(212404);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/11");

  script_cve_id("CVE-2019-14379", "CVE-2020-2560", "CVE-2020-2564");

  script_name(english:"Oracle Siebel Server < 19.11 (January 2020 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The versions of Oracle Siebel CRM installed on the remote host are affected by multiple vulnerabilities as referenced in
the January 2020 CPU advisory.

  - Vulnerability in the Siebel UI Framework product of Oracle Siebel CRM (component: EAI (jackson-databind)).
    Supported versions that are affected are 19.10 and prior. Easily exploitable vulnerability allows
    unauthenticated attacker with network access via HTTP to compromise Siebel UI Framework. Successful
    attacks of this vulnerability can result in takeover of Siebel UI Framework. (CVE-2019-14379)

  - Vulnerability in the Siebel UI Framework product of Oracle Siebel CRM (component: EAI). Supported versions
    that are affected are 19.10 and prior. Easily exploitable vulnerability allows unauthenticated attacker
    with network access via HTTP to compromise Siebel UI Framework. Successful attacks of this vulnerability
    can result in unauthorized read access to a subset of Siebel UI Framework accessible data. (CVE-2020-2564)

  - Vulnerability in the Siebel UI Framework product of Oracle Siebel CRM (component: SWSE Server). Supported
    versions that are affected are 19.10 and prior. Easily exploitable vulnerability allows unauthenticated
    attacker with network access via HTTP to compromise Siebel UI Framework. Successful attacks require human
    interaction from a person other than the attacker and while the vulnerability is in Siebel UI Framework,
    attacks may significantly impact additional products. Successful attacks of this vulnerability can result
    in unauthorized read access to a subset of Siebel UI Framework accessible data. (CVE-2020-2560)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpujan2020cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujan2020.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2020 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-14379");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:siebel_crm");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_siebel_server_installed.nbin");
  script_require_keys("installed_sw/Oracle Siebel Server");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Oracle Siebel Server');

var constraints = [
  { 'fixed_version' : '19.11' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
