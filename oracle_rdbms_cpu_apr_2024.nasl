#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(193497);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/02");

  script_cve_id(
    "CVE-2022-34169",
    "CVE-2022-34381",
    "CVE-2023-28823",
    "CVE-2023-36632",
    "CVE-2023-39975",
    "CVE-2023-42503",
    "CVE-2023-47038",
    "CVE-2023-48795",
    "CVE-2023-5072",
    "CVE-2024-20995",
    "CVE-2024-21058",
    "CVE-2024-21066",
    "CVE-2024-21093",
    "CVE-2024-23672"
  );

  script_name(english:"Oracle Database Server (Apr 2024 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The versions of Oracle Database Server installed on the remote host are affected by multiple vulnerabilities as
referenced in the April 2024 CPU advisory.

  - Vulnerability in the RDBMS (Python) component of Oracle Database Server. Supported versions that are 
    affected are 21.3-21.13. Easily exploitable vulnerability allows low privileged attacker having 
    Authenticated User privilege with network access via Oracle Net to compromise RDBMS (Python). Successful 
    attacks require human interaction from a person other than the attacker. Successful attacks of this 
    vulnerability can result in unauthorized ability to cause a partial denial of service (partial DOS) 
    of RDBMS (Python). (CVE-2023-36632) 

  - Vulnerability in the Grid Infrastructure (Apache Mina SSHD) component of Oracle Database Server. 
  Supported versions that are affected are 21.3-21.13. Difficult to exploit vulnerability allows 
  unauthenticated attacker with network access via SSH to compromise Grid Infrastructure (Apache Mina SSHD). 
  Successful attacks of this vulnerability can result in unauthorized creation, deletion or modification 
  access to critical data or all Grid Infrastructure (Apache Mina SSHD) accessible data. (CVE-2023-48795)

  - Vulnerability in the Oracle SQLcl (Apache Mina SSHD) component of Oracle Database Server. Supported 
  versions that are affected are 19.3-19.22 and 21.3-21.13. Difficult to exploit vulnerability allows 
  unauthenticated attacker with network access via SSH to compromise Oracle SQLcl (Apache Mina SSHD). 
  Successful attacks of this vulnerability can result in unauthorized creation, deletion or modification 
  access to critical data or all Oracle SQLcl (Apache Mina SSHD) accessible data. (CVE-2023-48795)	

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpuapr2024csaf.json");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuapr2024.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2024 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-34381");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:database_server");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_rdbms_query_patch_info.nbin", "oracle_rdbms_patch_info.nbin");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_oracle.inc');

var app_info = vcf::oracle_rdbms::get_app_info();

var constraints = [
  # RDBMS:
  {'min_version': '21.0', 'fixed_version': '21.13.0.0.240116', 'missing_patch':'36219877', 'os':'win', 'component':'db'},
  {'min_version': '21.0', 'fixed_version': '21.13.0.0.240416', 'missing_patch':'36352352', 'os':'unix', 'component':'db'},

  {'min_version': '19.0', 'fixed_version': '19.23.0.0.240416', 'missing_patch':'36219938', 'os':'win', 'component':'db'},
  {'min_version': '19.0', 'fixed_version': '19.23.0.0.240416', 'missing_patch':'36233263', 'os':'unix', 'component':'db'},

  {'min_version': '19.0',  'fixed_version': '19.23.0.0.240416', 'missing_patch':'36199232', 'os':'win', 'component':'ojvm'},
  {'min_version': '19.0',  'fixed_version': '19.23.0.0.240416', 'missing_patch':'36199232', 'os':'unix', 'component':'ojvm'}

];

vcf::oracle_rdbms::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
