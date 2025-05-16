#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(234555);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/17");

  script_cve_id(
    "CVE-2023-24998",
    "CVE-2024-38820",
    "CVE-2025-30723",
    "CVE-2025-30724"
  );
  script_xref(name:"IAVA", value:"2025-A-0269");

  script_name(english:"Oracle Business Intelligence Publisher 7.6 (OAS) (April 2025 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The versions of Oracle Business Intelligence Publisher (OAS) installed on the remote host are affected by 
multiple vulnerabilities as referenced in the April 2025 CPU advisory.

  - Vulnerability in the Oracle BI Publisher product of Oracle Analytics (component: Development Operations
    (Apache Commons FileUpload)). Supported versions that are affected are 7.6.0.0.0 and 12.2.1.4.0. Easily
    exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise
    Oracle BI Publisher. Successful attacks of this vulnerability can result in unauthorized ability to
    cause a hang or frequently repeatable crash (complete DOS) of Oracle BI Publisher. (CVE-2023-24998)

  - Vulnerability in the Oracle BI Publisher product of Oracle Analytics (component: Development Operations
    (Spring Framework)). The supported version that is affected is 7.6.0.0.0. Easily exploitable vulnerability
    allows unauthenticated attacker with network access via multiple protocols to compromise Oracle BI
    Publisher. Successful attacks of this vulnerability can result in unauthorized update, insert or delete
    access to some of Oracle BI Publisher accessible data. (CVE-2024-38820)

  - Vulnerability in the Oracle BI Publisher product of Oracle Analytics (component: XML Services). Supported
    versions that are affected are 7.6.0.0.0 and 12.2.1.4.0. Easily exploitable vulnerability allows low
    privileged attacker with network access via HTTP to compromise Oracle BI Publisher. Successful attacks
    of this vulnerability can result in unauthorized update, insert or delete access to some of Oracle BI
    Publisher accessible data and unauthorized ability to cause a partial denial of service (partial DOS)
    of Oracle BI Publisher. (CVE-2025-30723)

  - Vulnerability in the Oracle BI Publisher product of Oracle Analytics (component: XML Services). Supported
    versions that are affected are 7.6.0.0.0 and 12.2.1.4.0. Easily exploitable vulnerability allows
    unauthenticated attacker with network access via HTTP to compromise Oracle BI Publisher. Successful
    attacks of this vulnerability can result in unauthorized access to critical data or complete access to
    all Oracle BI Publisher accessible data. (CVE-2025-30724)


Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuapr2025.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2025 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-24998");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/04/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:business_intelligence_publisher");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_bi_publisher_installed.nbin");
  script_require_keys("installed_sw/Oracle Business Intelligence Publisher");

  exit(0);
}

include('vcf_extras.inc');

var app_info = vcf::get_app_info(app:'Oracle Business Intelligence Publisher');

var constraints = [
  # Oracle Analytics Server 7.6
  {'min_version': '12.2.7.6.0', 'fixed_version': '12.2.7.6.250403', 'patch': '37788262', 'bundle': 'Not yet released'},
];

vcf::oracle_bi_publisher::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);

