#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(209385);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/22");

  script_cve_id("CVE-2024-29025", "CVE-2024-29131", "CVE-2024-29133");

  script_name(english:"Oracle NoSQL Database (October 2024 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The 1.5.0, 20.3.40, 21.2.71, 22.3.45, 23.3.33, and 24.1.17 versions of NoSQL Database installed on the remote host are
affected by multiple vulnerabilities as referenced in the October 2024 CPU advisory.

  - Vulnerability in Oracle NoSQL Database (component: Administration (Netty)). Supported versions that are
    affected are 20.3.40, 21.2.71, 22.3.45, 23.3.33 and 24.1.17. Easily exploitable vulnerability allows low
    privileged attacker with network access via HTTP to compromise Oracle NoSQL Database. Successful attacks
    of this vulnerability can result in unauthorized ability to cause a partial denial of service (partial
    DOS) of Oracle NoSQL Database. (CVE-2024-29025)

  - Security-in-Depth issue in Oracle NoSQL Database (component: Administration (Apache Commons
    Configuration)). This vulnerability cannot be exploited in the context of this product. (CVE-2024-29131,
    CVE-2024-29133)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpuoct2024csaf.json");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuoct2024.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2024 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-29025");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-29131");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:oracle:nosql_database");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_nosql_nix_installed.nbin");
  script_require_keys("installed_sw/Oracle NoSQL Database");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Oracle NoSQL Database');

var constraints =[ {'fixed_version' : '24.1.17'} ];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
