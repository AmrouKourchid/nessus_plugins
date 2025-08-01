#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(189737);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/25");

  script_cve_id("CVE-2024-20979", "CVE-2024-20987");

  script_name(english:"Oracle Business Intelligence Publisher (January 2024 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The versions of Oracle Business Intelligence Publisher installed on the remote host are
affected by multiple vulnerabilities as referenced in the January 2024 CPU advisory.

  - Vulnerability in the Oracle BI Publisher product of Oracle Analytics (component: Web Server). Supported 
    versions that are affected are 6.4.0.0.0, 7.0.0.0.0 and 12.2.1.4.0. Easily exploitable vulnerability 
    allows low privileged attacker with network access via HTTP to compromise Oracle BI Publisher. Successful 
    attacks require human interaction from a person other than the attacker and while the vulnerability is in 
    Oracle BI Publisher, attacks may significantly impact additional products (scope change). Successful 
    attacks of this vulnerability can result in unauthorized update, insert or delete access to some of Oracle 
    BI Publisher accessible data as well as unauthorized read access to a subset of Oracle BI Publisher 
    accessible data. (CVE-2024-20979)

  - Vulnerability in the Oracle BI Publisher product of Oracle Analytics (component: Web Server). The 
    supported version that is affected is 12.2.1.4.0. Easily exploitable vulnerability allows low privileged 
    attacker with network access via HTTP to compromise Oracle BI Publisher. Successful attacks require human 
    interaction from a person other than the attacker and while the vulnerability is in Oracle BI Publisher, 
    attacks may significantly impact additional products (scope change). Successful attacks of this 
    vulnerability can result in unauthorized update, insert or delete access to some of Oracle BI Publisher 
    accessible data as well as unauthorized read access to a subset of Oracle BI Publisher accessible data. 
    (CVE-2024-20987)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujan2024.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2024 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20987");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:business_intelligence_publisher");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_bi_publisher_installed.nbin");
  script_require_keys("installed_sw/Oracle Business Intelligence Publisher");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::get_app_info(app:'Oracle Business Intelligence Publisher');

# based on Oracle CPU data
var constraints = [
  {'min_version': '12.2.1.4', 'fixed_version': '12.2.1.4.240112', 'patch': '36180701', 'bundle': '36194105'}
];

vcf::oracle_bi_publisher::check_version_and_report(app_info: app_info, constraints:constraints, severity:SECURITY_WARNING);
