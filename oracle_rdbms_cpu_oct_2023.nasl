#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(183503);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/18");

  script_cve_id(
    "CVE-2021-24031",
    "CVE-2022-23491",
    "CVE-2022-40896",
    "CVE-2022-40897",
    "CVE-2022-42004",
    "CVE-2022-44729",
    "CVE-2022-46908",
    "CVE-2023-2976",
    "CVE-2023-22071",
    "CVE-2023-22073",
    "CVE-2023-22074",
    "CVE-2023-22075",
    "CVE-2023-22077",
    "CVE-2023-22096",
    "CVE-2023-28320",
    "CVE-2023-28321",
    "CVE-2023-28322",
    "CVE-2023-35116",
    "CVE-2023-35887",
    "CVE-2023-38039",
    "CVE-2023-38325"
  );
  script_xref(name:"IAVA", value:"2023-A-0556");
  script_xref(name:"IAVA", value:"2023-A-0558");
  script_xref(name:"IAVA", value:"2023-A-0559");
  script_xref(name:"IAVA", value:"2023-A-0562");
  script_xref(name:"IAVA", value:"2023-A-0554-S");

  script_name(english:"Oracle Database Server (October 2023 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The versions of Oracle Database Server installed on the remote host are affected by multiple vulnerabilities as
referenced in the October 2023 CPU advisory.

  - Vulnerability in the Oracle Spatial and Graph (cURL) component of Oracle Database Server. Supported
    versions that are affected are 19.3-19.20 and 21.3-21.11. Easily exploitable vulnerability allows low
    privileged attacker having Authenticated User privilege with network access via HTTP to compromise Oracle
    Spatial and Graph (cURL). Successful attacks of this vulnerability can result in unauthorized ability to
    cause a hang or frequently repeatable crash (complete DOS) of Oracle Spatial and Graph (cURL).
    (CVE-2023-38039)

  - Vulnerability in the OML4Py (cryptography) component of Oracle Database Server. Supported versions that
    are affected are 21.3-21.11. Difficult to exploit vulnerability allows unauthenticated attacker with
    network access via HTTP to compromise OML4Py (cryptography). Successful attacks of this vulnerability can
    result in unauthorized creation, deletion or modification access to critical data or all
    OML4Py (cryptography) accessible data. (CVE-2022-23491)

  - Vulnerability in the PL/SQL component of Oracle Database Server. Supported versions that are affected are
    19.3-19.20 and 21.3-21.11. Easily exploitable vulnerability allows high privileged attacker having Create
    Session, Execute on sys.utl_http privilege with network access via Oracle Net to compromise PL/SQL.
    Successful attacks require human interaction from a person other than the attacker and while the
    vulnerability is in PL/SQL, attacks may significantly impact additional products (scope change).
    Successful attacks of this vulnerability can result in unauthorized update, insert or delete access to
    some of PL/SQL accessible data as well as unauthorized read access to a subset of PL/SQL accessible data
    and unauthorized ability to cause a partial denial of service (partial DOS) of PL/SQL. (CVE-2023-22071)

  - Security-in-depth update for non-exploitable vulnerabilities CVE-2020-25649, CVE-2020-36518, CVE-2021-34031,
    CVE-2022-4899, CVE-2022-42003, CVE-2022-42004, CVE-2022-46908, CVE-2023-2976 and CVE-2023-35887.


Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpuoct2023cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuoct2023.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2023 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"CVSS vector from vendor advisory");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/20");

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
  {'min_version': '21.0', 'fixed_version': '21.12.0.0.231017', 'missing_patch':'35681617', 'os':'win', 'component':'db'},
  {'min_version': '21.0', 'fixed_version': '21.12.0.0.231017', 'missing_patch':'35740258', 'os':'unix', 'component':'db'},

  {'min_version': '19.0', 'fixed_version': '19.21.0.0.231017', 'missing_patch':'35681522', 'os':'win', 'component':'db'},
  {'min_version': '19.0', 'fixed_version': '19.21.0.0.231017', 'missing_patch':'35643107', 'os':'unix', 'component':'db'},

  # OJVM:
  {'min_version': '19.0',  'fixed_version': '19.21.0.0.231017', 'missing_patch':'35648110', 'os':'win', 'component':'ojvm'},
  {'min_version': '19.0',  'fixed_version': '19.21.0.0.231017', 'missing_patch':'35648110', 'os':'unix', 'component':'ojvm'}

];

vcf::oracle_rdbms::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
