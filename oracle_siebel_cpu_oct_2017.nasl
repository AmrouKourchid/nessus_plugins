#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(212384);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/11");

  script_cve_id(
    "CVE-2013-1903",
    "CVE-2017-10162",
    "CVE-2017-10263",
    "CVE-2017-10264",
    "CVE-2017-10300",
    "CVE-2017-10302",
    "CVE-2017-10315",
    "CVE-2017-10333"
  );

  script_name(english:"Oracle Siebel CRM (October 2017 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The versions of Oracle Siebel CRM installed on the remote host are affected by multiple vulnerabilities as referenced in
the October 2017 CPU advisory.

  - Vulnerability in the Siebel Apps - Field Service component of Oracle Siebel CRM (subcomponent: Smart
    Answer (Python)). Supported versions that are affected are 16.0 and 17.0. Easily exploitable vulnerability
    allows unauthenticated attacker with network access via HTTP to compromise Siebel Apps - Field Service.
    While the vulnerability is in Siebel Apps - Field Service, attacks may significantly impact additional
    products. Successful attacks of this vulnerability can result in takeover of Siebel Apps - Field Service.
    (CVE-2013-1903)

  - Vulnerability in the Siebel UI Framework component of Oracle Siebel CRM (subcomponent: UIF Open UI).
    Supported versions that are affected are 16.0 and 17.0. Easily exploitable vulnerability allows
    unauthenticated attacker with network access via HTTP to compromise Siebel UI Framework. Successful
    attacks require human interaction from a person other than the attacker and while the vulnerability is in
    Siebel UI Framework, attacks may significantly impact additional products. Successful attacks of this
    vulnerability can result in unauthorized access to critical data or complete access to all Siebel UI
    Framework accessible data as well as unauthorized update, insert or delete access to some of Siebel UI
    Framework accessible data. (CVE-2017-10263)

  - Vulnerability in the Siebel UI Framework component of Oracle Siebel CRM (subcomponent: EAI). Supported
    versions that are affected are 16.0 and 17.0. Easily exploitable vulnerability allows low privileged
    attacker with network access via HTTP to compromise Siebel UI Framework. While the vulnerability is in
    Siebel UI Framework, attacks may significantly impact additional products. Successful attacks of this
    vulnerability can result in unauthorized update, insert or delete access to some of Siebel UI Framework
    accessible data as well as unauthorized read access to a subset of Siebel UI Framework accessible data and
    unauthorized ability to cause a partial denial of service (partial DOS) of Siebel UI Framework.
    (CVE-2017-10333)

  - Vulnerability in the Siebel UI Framework component of Oracle Siebel CRM (subcomponent: UIF Open UI).
    Supported versions that are affected are 16.0 and 17.0. Easily exploitable vulnerability allows
    unauthenticated attacker with network access via HTTP to compromise Siebel UI Framework. Successful
    attacks require human interaction from a person other than the attacker and while the vulnerability is in
    Siebel UI Framework, attacks may significantly impact additional products. Successful attacks of this
    vulnerability can result in unauthorized update, insert or delete access to some of Siebel UI Framework
    accessible data as well as unauthorized read access to a subset of Siebel UI Framework accessible data.
    (CVE-2017-10302, CVE-2017-10315)

  - Vulnerability in the Siebel Core - Server Framework component of Oracle Siebel CRM (subcomponent:
    Services). Supported versions that are affected are 16.0 and 17.0. Easily exploitable vulnerability allows
    low privileged attacker with network access via HTTP to compromise Siebel Core - Server Framework.
    Successful attacks of this vulnerability can result in unauthorized update, insert or delete access to
    some of Siebel Core - Server Framework accessible data as well as unauthorized read access to a subset of
    Siebel Core - Server Framework accessible data. (CVE-2017-10162)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # http://www.oracle.com/technetwork/security-advisory/cpuoct2017-3236626.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1e07fa0e");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2017 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-1903");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2017-10263");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:siebel_crm");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_siebel_server_installed.nbin");
  script_require_keys("installed_sw/Oracle Siebel Server");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Oracle Siebel Server');

var constraints = [
  { 'min_version' : '8.1.1', 'fixed_version' : '8.1.1.16.18' },
  { 'min_version' : '8.1.1.17', 'fixed_version' : '8.1.1.17.1' },
  { 'min_version' : '8.2.2', 'fixed_version' : '8.2.2.16.18' },
  { 'min_version' : '8.2.2.17', 'fixed_version' : '8.2.2.17.1' },
  { 'min_version' : '15', 'fixed_version' : '16.18' },
  { 'min_version' : '17', 'fixed_version' : '17.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
