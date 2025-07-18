#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(166336);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/10/24");

  script_cve_id("CVE-2021-36518", "CVE-2022-24729", "CVE-2022-33980");
  script_xref(name:"IAVA", value:"2023-A-0558");

  script_name(english:"Oracle Business Intelligence Publisher 5.9.x < 5.9.0 (OAS) (Oct 2022 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The versions of Oracle Business Intelligence Enterprise Edition (OAS) installed
on the remote host are affected by multiple vulnerabilities as referenced in the October 2022 CPU advisory.

  - Vulnerability in the Oracle WebCenter Sites product of Oracle Fusion Middleware (component: WebCenter
    Sites (CKEditor)). Supported versions that are affected are 12.2.1.3.0 and 12.2.1.4.0. Easily exploitable
    vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle WebCenter
    Sites. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or
    frequently repeatable crash (complete DOS) of Oracle WebCenter Sites. (CVE-2022-24729)

  - Vulnerability in the Oracle Hyperion Infrastructure Technology product of Oracle Hyperion (component:
    Installation and Configuration (Apache Commons Configuration)). The supported version that is affected is
    11.2.9. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to
    compromise Oracle Hyperion Infrastructure Technology. Successful attacks of this vulnerability can result
    in takeover of Oracle Hyperion Infrastructure Technology. (CVE-2022-33980)

  - jackson-databind before 2.13.0 allows a Java StackOverflow exception and denial of service via a large
    depth of nested objects. (CVE-2020-36518)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpuOct2022cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuOct2022.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the Oct 2022 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-33980");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:business_intelligence_publisher");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_bi_publisher_installed.nbin");
  script_require_keys("installed_sw/Oracle Business Intelligence Publisher");

  exit(0);
}

include('vcf_extras.inc');

var app_info = vcf::get_app_info(app:'Oracle Business Intelligence Publisher');

var constraints = [
  # Oracle Analytics Server 6.4
  {'min_version': '12.2.6.4.0', 'fixed_version': '12.2.6.4.220926', 'patch': '34624887', 'bundle': '34690622'}
];

vcf::oracle_bi_publisher::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
