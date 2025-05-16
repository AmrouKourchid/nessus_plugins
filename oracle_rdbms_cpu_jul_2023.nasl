#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(178468);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/13");

  script_cve_id(
    "CVE-2021-3520",
    "CVE-2022-21189",
    "CVE-2022-45143",
    "CVE-2023-21949",
    "CVE-2023-22034",
    "CVE-2023-22052",
    "CVE-2023-23931",
    "CVE-2023-24998",
    "CVE-2023-28708",
    "CVE-2023-28709",
    "CVE-2023-30533",
    "CVE-2023-34981",
    "CVE-2022-43680"
  );
  script_xref(name:"IAVA", value:"2023-A-0360-S");
  script_xref(name:"IAVA", value:"2023-A-0559");

  script_name(english:"Oracle Database Server (Jul 2023 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The 19c and 21c versions of Oracle Database Server installed on the remote host are affected by multiple vulnerabilities
as referenced in the July CPU advisory.

  - Vulnerability in the Oracle Text (LibExpat) component of Oracle Database Server. Supported versions that
    are affected are 19.3-19.19 and 21.3-21.10. Easily exploitable vulnerability allows low privileged
    attacker having Create Session, Create Index privilege with network access via Oracle Net to compromise
    Oracle Text (LibExpat). Successful attacks of this vulnerability can result in unauthorized ability to
    cause a hang or frequently repeatable crash (complete DOS) of Oracle Text (LibExpat). (CVE-2022-43680)

  - Vulnerability in the Advanced Networking Option component of Oracle Database Server. Supported versions
    that are affected are 19.3-19.19 and 21.3-21.10. Difficult to exploit vulnerability allows
    unauthenticated attacker with network access via Oracle Net to compromise Advanced Networking Option.
    Successful attacks of this vulnerability can result in unauthorized update, insert or delete access to
    some of Advanced Networking Option accessible data. (CVE-2023-21949)

  - Vulnerability in the Unified Audit component of Oracle Database Server. Supported versions that are
    affected are 19.3-19.19 and 21.3-21.10. Easily exploitable vulnerability allows high privileged
    attacker having SYSDBA privilege with network access via Oracle Net to compromise Unified Audit.
    Successful attacks of this vulnerability can result in unauthorized creation, deletion or modification
    access to critical data or all Unified Audit accessible data. (CVE-2023-22034)

  - Security-in-depth updates for CVE-2021-3520, CVE-2022-21189, CVE-2022-45143, CVE-2023-24998, CVE-2023-28708,
    CVE-2023-28709, CVE-2023-30533 and CVE-2023-34981

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpujul2023cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujul2023.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2023 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-21189");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/07/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:database_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_rdbms_query_patch_info.nbin", "oracle_rdbms_patch_info.nbin");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_oracle.inc');

var app_info = vcf::oracle_rdbms::get_app_info();

var constraints = [
  # RDBMS:
  {'min_version': '21.0', 'fixed_version': '21.11.0.0.230718', 'missing_patch':'35347974', 'os':'win', 'component':'db'},
  {'min_version': '21.0', 'fixed_version': '21.11.0.0.230718', 'missing_patch':'35428978', 'os':'unix', 'component':'db'},

  {'min_version': '19.0', 'fixed_version': '19.20.0.0.230718', 'missing_patch':'35348034', 'os':'win', 'component':'db'},
  {'min_version': '19.0', 'fixed_version': '19.20.0.0.230718', 'missing_patch':'35320081', 'os':'unix', 'component':'db'},

  # OJVM:
  {'min_version': '19.0',  'fixed_version': '19.20.0.0.230718', 'missing_patch':'35354406', 'os':'win', 'component':'ojvm'},
  {'min_version': '19.0',  'fixed_version': '19.20.0.0.230718', 'missing_patch':'35354406', 'os':'unix', 'component':'ojvm'}

];

vcf::oracle_rdbms::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
