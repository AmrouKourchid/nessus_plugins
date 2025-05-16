#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(178712);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/25");

  script_cve_id(
    "CVE-2023-20861",
    "CVE-2022-24891",
    "CVE-2023-30535",
    "CVE-2022-46364"
  );

  script_name(english:"Oracle Business Intelligence Publisher (OBIEE) (July 2023 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The 5.9.0.0 and 6.4.0.0 versions of Oracle Business Intelligence Enterprise Edition installed on the remote host are
affected by multiple vulnerabilities as referenced in the July 2023 CPU advisory.

  - Vulnerability in the BI Publisher product of Oracle Analytics (component: Security (Apache CXF)). The
    supported version that is affected is 6.4.0.0.0. Easily exploitable vulnerability allows unauthenticated attacker
    with network access via HTTP to compromise BI Publisher. Successful attacks of this vulnerability can result in
    takeover of BI Publisher. (CVE-2022-46364)

  - Vulnerability in the BI Publisher product of Oracle Analytics (component: Development Operations (Snowflake
    JDBC)). The supported version that is affected is 7.0.0.0.0. Easily exploitable vulnerability allows
    unauthenticated attacker with network access via HTTP to compromise BI Publisher. Successful attacks require human
    interaction from a person other than the attacker. Successful attacks of this vulnerability can result in takeover
    of BI Publisher. (CVE-2023-30535)

  - Vulnerability in the BI Publisher product of Oracle Analytics (component: Web Server (Spring Framework)).
    Supported versions that are affected are 6.4.0.0.0 and 7.0.0.0.0. Easily exploitable vulnerability allows low
    privileged attacker with network access via HTTP to compromise BI Publisher. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of BI
    Publisher. (CVE-2023-20861)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujul2023.html");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpujul2023cvrf.xml");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2023 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-24891");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-46364");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/07/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:business_intelligence_publisher");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_bi_publisher_installed.nbin");
  script_require_keys("installed_sw/Oracle Business Intelligence Publisher");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::get_app_info(app:'Oracle Business Intelligence Publisher');

# based on Oracle CPU data
var constraints = [
  {'min_version': '12.2.1.4', 'fixed_version': '12.2.1.4.230628', 'patch': '35548198', 'bundle': '35601492'}
];

vcf::oracle_bi_publisher::check_version_and_report(app_info: app_info, constraints:constraints, severity:SECURITY_WARNING);
