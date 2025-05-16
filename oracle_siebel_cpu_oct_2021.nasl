#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(212425);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/12");

  script_cve_id(
    "CVE-2016-2183",
    "CVE-2020-9484",
    "CVE-2020-9488",
    "CVE-2021-25122",
    "CVE-2021-26272",
    "CVE-2021-28165"
  );
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"Oracle Siebel Server (October 2021 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The versions of Oracle Siebel CRM installed on the remote host are affected by multiple vulnerabilities as referenced in
the October 2021 CPU advisory.

  - Vulnerability in the Siebel Core - Automation product of Oracle Siebel CRM (component: Test Automation
    (Eclipse Jetty)). Supported versions that are affected are 21.9 and prior. Easily exploitable
    vulnerability allows unauthenticated attacker with network access via TLS to compromise Siebel Core -
    Automation. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or
    frequently repeatable crash (complete DOS) of Siebel Core - Automation. (CVE-2021-28165)

  - Vulnerability in the Siebel UI Framework product of Oracle Siebel CRM (component: EAI (Apache Tomcat)).
    Supported versions that are affected are 21.9 and prior. Easily exploitable vulnerability allows
    unauthenticated attacker with network access via HTTP to compromise Siebel UI Framework. Successful
    attacks of this vulnerability can result in unauthorized access to critical data or complete access to all
    Siebel UI Framework accessible data. (CVE-2021-25122)

  - Vulnerability in the Siebel UI Framework product of Oracle Siebel CRM (component: EAI, SWSE (OpenSSL)).
    Supported versions that are affected are 21.9 and prior. Easily exploitable vulnerability allows
    unauthenticated attacker with network access via TLS to compromise Siebel UI Framework. Successful attacks
    of this vulnerability can result in unauthorized access to critical data or complete access to all Siebel
    UI Framework accessible data. (CVE-2016-2183)

  - Vulnerability in the Siebel Apps - Marketing product of Oracle Siebel CRM (component: Marketing (Apache
    Tomcat)). Supported versions that are affected are 21.9 and prior. Difficult to exploit vulnerability
    allows low privileged attacker with logon to the infrastructure where Siebel Apps - Marketing executes to
    compromise Siebel Apps - Marketing. Successful attacks of this vulnerability can result in takeover of
    Siebel Apps - Marketing. (CVE-2020-9484)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpuoct2021cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuoct2021.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2021 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-25122");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/19");
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
  { 'fixed_version' : '21.10' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
