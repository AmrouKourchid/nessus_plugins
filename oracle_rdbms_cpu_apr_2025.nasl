#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(234618);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/19");

  script_cve_id(
    "CVE-2020-36843",
    "CVE-2022-3786",
    "CVE-2024-6763",
    "CVE-2024-8176",
    "CVE-2024-8184",
    "CVE-2024-9143",
    "CVE-2024-11053",
    "CVE-2024-13176",
    "CVE-2025-24813",
    "CVE-2025-30694",
    "CVE-2025-30701",
    "CVE-2025-30702",
    "CVE-2025-30733",
    "CVE-2025-30736"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2025/04/22");
  script_xref(name:"IAVA", value:"2025-A-0263");
  script_xref(name:"CEA-ID", value:"CEA-2022-0036");

  script_name(english:"Oracle Database Server (April 2025 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The versions of Oracle Database Server installed on the remote host are affected by multiple vulnerabilities as
referenced in the April 2025 CPU advisory.

  - Security-in-Depth issue in the Oracle Database Grid (Apache Tomcat) component of Oracle Database
    Server. This vulnerability cannot be exploited in the context of this product. (CVE-2025-24813)

  - Vulnerability in the Oracle Database (OpenSSL) component of Oracle Database Server.  Supported versions
    that are affected are 23.4-23.7. Easily exploitable vulnerability allows physical access to compromise
    Oracle Database (OpenSSL).  Successful attacks of this vulnerability can result in  unauthorized update,
    insert or delete access to some of Oracle Database (OpenSSL) accessible data as well as  unauthorized read
    access to a subset of Oracle Database (OpenSSL) accessible data and unauthorized ability to cause a partial
    denial of service (partial DOS) of Oracle Database (OpenSSL). CVSS 3.1 Base Score 4.3 (Confidentiality,
    Integrity and Availability impacts). (CVE-2024-9143)

  - Vulnerability in the Oracle Database SQLCl (EdDSA) component of Oracle Database Server.  Supported versions
    that are affected are 23.4-23.7. Easily exploitable vulnerability allows unauthenticated attacker with logon
    to the infrastructure where Oracle Database SQLCl (EdDSA) executes to compromise Oracle Database SQLCl
    (EdDSA).  While the vulnerability is in Oracle Database SQLCl (EdDSA), attacks may significantly impact
    additional products (scope change).  Successful attacks of this vulnerability can result in  unauthorized
    update, insert or delete access to some of Oracle Database SQLCl (EdDSA) accessible data. (CVE-2020-36843)

  - Vulnerability in the Oracle Database (OpenSSL) component of Oracle Database Server.  Supported versions
    that are affected are 23.4-23.7. Easily exploitable vulnerability allows physical access to compromise
    Oracle Database (OpenSSL).  Successful attacks of this vulnerability can result in  unauthorized update,
    insert or delete access to some of Oracle Database (OpenSSL) accessible data as well as  unauthorized
    read access to a subset of Oracle Database (OpenSSL) accessible data and unauthorized ability to cause
    a partial denial of service (partial DOS) of Oracle Database (OpenSSL). (CVE-2022-3786)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpuapr2025csaf.json");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuapr2025.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2025 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:A");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-9143");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2025-24813");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/04/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:database_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_rdbms_query_patch_info.nbin", "oracle_rdbms_patch_info.nbin");

  exit(0);
}

include('vcf_extras_oracle.inc');

var app_info = vcf::oracle_rdbms::get_app_info();

var constraints = [
  # RDBMS:
  {'min_version': '23.0', 'fixed_version': '23.8.0.25.04', 'missing_patch':'37701421', 'os':'unix', 'component':'db' },

  {'min_version': '21.0', 'fixed_version': '21.18.0.0.250415', 'missing_patch':'37655430', 'os':'unix', 'component':'db'},
  {'min_version': '21.0', 'fixed_version': '21.18.0.0.250415', 'missing_patch':'37532378', 'os':'win', 'component':'db'},

  {'min_version': '19.0', 'fixed_version': '19.27.0.0.250415', 'missing_patch':'37642901', 'os':'unix', 'component':'db'},
  {'min_version': '19.0', 'fixed_version': '19.27.0.0.250415', 'missing_patch':'37532350', 'os':'win', 'component':'db'},

  # OJVM:
  {'min_version': '19.0', 'fixed_version': '19.27.0.0.250415', 'missing_patch':'37499406 / 37591483', 'os':'unix', 'component':'ojvm'},

];

vcf::oracle_rdbms::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

