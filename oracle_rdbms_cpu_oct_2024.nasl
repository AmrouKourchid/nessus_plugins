#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(209306);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/24");

  script_cve_id(
    "CVE-2022-38136",
    "CVE-2022-40196",
    "CVE-2022-41342",
    "CVE-2023-4043",
    "CVE-2024-5535",
    "CVE-2024-6119",
    "CVE-2024-6232",
    "CVE-2024-7264",
    "CVE-2024-7592",
    "CVE-2024-21131",
    "CVE-2024-21138",
    "CVE-2024-21140",
    "CVE-2024-21144",
    "CVE-2024-21145",
    "CVE-2024-21147",
    "CVE-2024-21233",
    "CVE-2024-21242",
    "CVE-2024-21251",
    "CVE-2024-27983",
    "CVE-2024-28182",
    "CVE-2024-28887",
    "CVE-2024-29025",
    "CVE-2024-34750",
    "CVE-2024-37370",
    "CVE-2024-37371",
    "CVE-2024-38998",
    "CVE-2024-38999",
    "CVE-2024-45490",
    "CVE-2024-45491",
    "CVE-2024-45492"
  );
  script_xref(name:"IAVA", value:"2024-A-0651-S");

  script_name(english:"Oracle Database Server (October 2024 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The versions of Oracle Database Server installed on the remote host are affected by multiple vulnerabilities as
referenced in the October 2024 CPU advisory.

  - Vulnerability in the Oracle Spatial and Graph (libcurl2) component of Oracle Database Server. Supported
    versions that are affected are 19.3-19.24, 21.3-21.15 and 23.4-23.5. Difficult to exploit vulnerability
    allows unauthenticated attacker with network access via HTTP to compromise Oracle Spatial and Graph
    (libcurl2). Successful attacks require human interaction from a person other than the attacker. Successful
    attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable
    crash (complete DOS) of Oracle Spatial and Graph (libcurl2). (CVE-2024-7264)

  - Vulnerability in the Oracle Database Security (OpenSSL) component of Oracle Database Server. Supported
    versions that are affected are 23.4-23.5. Easily exploitable vulnerability allows unauthenticated attacker
    with network access via multiple protocols to compromise Oracle Database Security (OpenSSL). Successful
    attacks of this vulnerability can result in unauthorized ability to cause a partial denial of service
    (partial DOS) of Oracle Database Security (OpenSSL). (CVE-2024-5535, CVE-2024-6119)

  - Vulnerability in the Fleet Patching and Provisioning - Micronaut (Netty) component of Oracle Database
    Server. Supported versions that are affected are 23.4-23.5. Easily exploitable vulnerability allows low
    privileged attacker having Authenticated User privilege with network access via HTTP to compromise Fleet
    Patching and Provisioning - Micronaut (Netty). Successful attacks of this vulnerability can result in
    unauthorized ability to cause a partial denial of service (partial DOS) of Fleet Patching and Provisioning
    - Micronaut (Netty). (CVE-2024-29025)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpuoct2024csaf.json");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuoct2024.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2024 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:L/AC:H/AT:P/PR:L/UI:A/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:P");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-45492");
  script_set_attribute(attribute:"cvss4_score_source", value:"CVE-2024-28887");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:database_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_rdbms_query_patch_info.nbin", "oracle_rdbms_patch_info.nbin");

  exit(0);
}

include('vcf_extras_oracle.inc');

var app_info = vcf::oracle_rdbms::get_app_info();

var constraints = [
  {'min_version': '19.0', 'fixed_version': '19.25.0.0.241015', 'missing_patch':'36878821','os':'win', 'component':'db' },
  {'min_version': '19.0', 'fixed_version': '19.25.0.0.241015', 'missing_patch':'36912597', 'os':'unix', 'component':'db'},

  {'min_version': '21.0', 'fixed_version': '21.16.0.0.241015', 'missing_patch':'36878842', 'os':'win', 'component':'db' },
  {'min_version': '21.0', 'fixed_version': '21.16.0.0.241015', 'missing_patch':'36991631', 'os':'unix', 'component':'db' },

  {'min_version': '23.0', 'fixed_version': '23.6.0.24.10', 'missing_patch':'37037086', 'os':'unix', 'component':'db' }
];

vcf::oracle_rdbms::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
