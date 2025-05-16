#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(189165);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/19");

  script_cve_id(
    "CVE-2022-21432",
    "CVE-2022-41409",
    "CVE-2022-46337",
    "CVE-2023-2976",
    "CVE-2023-4043",
    "CVE-2023-36479",
    "CVE-2023-38039",
    "CVE-2023-38545",
    "CVE-2023-38546",
    "CVE-2023-40167",
    "CVE-2023-41900",
    "CVE-2023-42794",
    "CVE-2023-42795",
    "CVE-2023-44487",
    "CVE-2023-45648",
    "CVE-2023-46589",
    "CVE-2024-20903"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/10/31");
  script_xref(name:"CEA-ID", value:"CEA-2023-0052");
  script_xref(name:"CEA-ID", value:"CEA-2024-0004");
  script_xref(name:"IAVA", value:"2024-A-0027-S");

  script_name(english:"Oracle Database Server (January 2024 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The versions of Oracle Database Server installed on the remote host are affected by multiple vulnerabilities as
referenced in the January 2024 CPU advisory.

  - Vulnerability in the Java VM component of Oracle Database Server. Supported versions that are affected
    are 19.3-19.21 and 21.3-21.12. Easily exploitable vulnerability allows low privileged attacker having
    Create Session, Create Procedure privilege with network access via Oracle Net to compromise Java VM.
    Successful attacks of this vulnerability can result in unauthorized creation, deletion or modification
    access to critical data or all Java VM accessible data. (CVE-2024-20903)

  - Vulnerability in the Oracle Spatial and Graph (curl) component of Oracle Database Server. Supported
    versions that are affected are 19.3-19.21, 21.3-21.12 and 23.3. Easily exploitable vulnerability allows
    low privileged attacker having Authenticated User privilege with network access via HTTP to compromise
    Oracle Spatial and Graph (curl). Successful attacks of this vulnerability can result in unauthorized
    ability to cause a hang or frequently repeatable crash (complete DOS) of Oracle Spatial and Graph (curl).
    (CVE-2023-38545)

  - Vulnerability in the Oracle Text component of Oracle Database Server. Supported versions that are affected
    are 19.3-19.21. Easily exploitable vulnerability allows high privileged attacker having DBA privilege with
    network access via Oracle Net to compromise Oracle Text. Successful attacks of this vulnerability can
    result in unauthorized ability to cause a partial denial of service (partial DOS) of Oracle Text.
    (CVE-2022-21432)

  - Security-in-depth update for non-exploitable vulnerabilities CVE-2022-41409, CVE-2022-46337, CVE-2023-2976,
    CVE-2023-4043, CVE-2023-36479, CVE-2023-40167, CVE-2023-41900, CVE-2023-42794, CVE-2023-42795,
    CVE-2023-44487, CVE-2023-45648 and CVE-2023-46589,.


Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpujan2024csaf.json");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujan2024.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2024 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"CVSS vector from vendor advisory");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:database_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_rdbms_query_patch_info.nbin", "oracle_rdbms_patch_info.nbin");

  exit(0);
}

include('vcf_extras_oracle.inc');

var app_info = vcf::oracle_rdbms::get_app_info();

var constraints = [
  # RDBMS:
  {'min_version': '21.0', 'fixed_version': '21.13.0.0.240116', 'missing_patch':'35962857', 'os':'win', 'component':'db'},
  {'min_version': '21.0', 'fixed_version': '21.13.0.0.240116', 'missing_patch':'36041222', 'os':'unix', 'component':'db'},

  {'min_version': '19.0', 'fixed_version': '19.22.0.0.240116', 'missing_patch':'35962832', 'os':'win', 'component':'db'},
  {'min_version': '19.0', 'fixed_version': '19.22.0.0.240116', 'missing_patch':'35943157', 'os':'unix', 'component':'db'},

  # OJVM:
  {'min_version': '19.0',  'fixed_version': '19.22.0.0.240116', 'missing_patch':'35926646', 'os':'win', 'component':'ojvm'},
  {'min_version': '19.0',  'fixed_version': '19.22.0.0.240116', 'missing_patch':'35926646', 'os':'unix', 'component':'ojvm'}

];

vcf::oracle_rdbms::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
