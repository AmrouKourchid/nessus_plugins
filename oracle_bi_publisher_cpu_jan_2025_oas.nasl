#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(214596);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/27");

  script_cve_id(
    "CVE-2016-1000027",
    "CVE-2024-7254",
    "CVE-2024-29025",
    "CVE-2024-38820",
    "CVE-2024-43382"
  );
  script_xref(name:"IAVA", value:"2025-A-0060");

  script_name(english:"Oracle Business Intelligence Publisher 7.0 / 7.6 (OAS) (January 2025 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The versions of Oracle Business Intelligence Publisher (OAS) installed on the remote host are affected by 
a vulnerability as referenced in the January 2025 CPU advisory.

  - Vulnerability in the Oracle BI Publisher product of Oracle Analytics (component: Development Operations 
    (Spring Framework)). Supported versions that are affected are 7.0.0.0.0 and 7.6.0.0.0. Easily exploitable 
    vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle BI 
    Publisher. Successful attacks of this vulnerability can result in takeover of Oracle BI Publisher.
    (CVE-2016-1000027)

  - Vulnerability in the Oracle BI Publisher product of Oracle Analytics (component: XML Services 
    (Snowflake JDBC)). Supported versions that are affected are 7.0.0.0.0 and 7.6.0.0.0. Difficult to exploit 
    vulnerability allows high privileged attacker with network access via HTTP to compromise Oracle BI 
    Publisher. Successful attacks of this vulnerability can result in unauthorized creation, deletion or 
    modification access to critical data or all Oracle BI Publisher accessible data as well as unauthorized 
    access to critical data or complete access to all Oracle BI Publisher accessible data. (CVE-2024-43382)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujan2025.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2025 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-1000027");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/01/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/01/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/01/24");

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
  # Oracle Analytics Server 7.0 / 7.6
  {'min_version': '12.2.7.0.0', 'fixed_version': '12.2.7.0.241230', 'patch': '37434763', 'bundle': '37476722'},
  {'min_version': '12.2.7.6.0', 'fixed_version': '12.2.7.6.241220', 'patch': '37415730', 'bundle': '37477637'},
];

vcf::oracle_bi_publisher::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);

