#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(212390);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/11");

  script_cve_id("CVE-2017-5645", "CVE-2018-1305", "CVE-2018-3059");

  script_name(english:"Oracle Siebel Server <= 18.9 (October 2018 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The versions of Oracle Siebel CRM installed on the remote host are affected by multiple vulnerabilities as referenced in
the October 2018 CPU advisory.

  - Vulnerability in the Siebel UI Framework component of Oracle Siebel CRM (subcomponent: EAI (Apache
    Log4j)). Supported versions that are affected are 18.7, 18.8 and 18.9. Easily exploitable vulnerability
    allows unauthenticated attacker with network access via HTTP to compromise Siebel UI Framework. Successful
    attacks of this vulnerability can result in takeover of Siebel UI Framework. (CVE-2017-5645)

  - Vulnerability in the MICROS XBRi component of Oracle Retail Applications (subcomponent: Retail (Apache
    Tomcat)). Supported versions that are affected are 10.8.3, 10.8.2, 10.8.1, 10.7.0, 10.6.0 and 10.5.0.
    Easily exploitable vulnerability allows low privileged attacker with network access via HTTP to compromise
    MICROS XBRi. Successful attacks of this vulnerability can result in unauthorized access to critical data
    or complete access to all MICROS XBRi accessible data. (CVE-2018-1305)

  - Vulnerability in the Siebel UI Framework component of Oracle Siebel CRM (subcomponent: UIF Open UI).
    Supported versions that are affected are 18.7, 18.8 and 18.9. Easily exploitable vulnerability allows
    unauthenticated attacker with network access via HTTP to compromise Siebel UI Framework. Successful
    attacks require human interaction from a person other than the attacker and while the vulnerability is in
    Siebel UI Framework, attacks may significantly impact additional products. Successful attacks of this
    vulnerability can result in unauthorized update, insert or delete access to some of Siebel UI Framework
    accessible data as well as unauthorized read access to a subset of Siebel UI Framework accessible data.
    (CVE-2018-3059)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # http://www.oracle.com/technetwork/security-advisory/cpuoct2018-4428296.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c526e694");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2018 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-5645");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/16");
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
  { 'min_version' : '18.7', 'max_version' : '18.9', 'fixed_display' : 'See vendor advisory' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
