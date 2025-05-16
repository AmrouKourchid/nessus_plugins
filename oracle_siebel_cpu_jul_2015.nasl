#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(212376);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/11");

  script_cve_id(
    "CVE-2015-2587",
    "CVE-2015-2600",
    "CVE-2015-2612",
    "CVE-2015-2649"
  );

  script_name(english:"Oracle Siebel CRM (July 2015 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The versions of Oracle Siebel CRM installed on the remote host are affected by multiple vulnerabilities as referenced in
the July 2015 CPU advisory.

  - Vulnerability in the Siebel UI Framework component of Oracle Siebel CRM (subcomponent: UIF Open UI).
    Supported versions that are affected are 8.1.1, 8.2.2 and 15.0. Difficult to exploit vulnerability allows
    successful authenticated network attacks via HTTPS. Successful attack of this vulnerability can result in
    unauthorized read access to a subset of Siebel UI Framework accessible data. (CVE-2015-2649)

  - Vulnerability in the Siebel Core - Server OM Svcs component of Oracle Siebel CRM (subcomponent: LDAP
    Security Adapter). Supported versions that are affected are 8.1.1, 8.2.2 and 15.0. Difficult to exploit
    vulnerability allows successful unauthenticated network attacks via HTTPS. Successful attack of this
    vulnerability can result in unauthorized read access to a subset of Siebel Core - Server OM Svcs
    accessible data. (CVE-2015-2612)

  - Vulnerability in the Siebel Core - Server OM Svcs component of Oracle Siebel CRM (subcomponent: Security).
    Supported versions that are affected are 8.1.1, 8.2.2 and 15.0. Difficult to exploit vulnerability allows
    successful authenticated network attacks via HTTPS. Successful attack of this vulnerability can result in
    unauthorized read access to a subset of Siebel Core - Server OM Svcs accessible data. (CVE-2015-2600)

  - Vulnerability in the Siebel UI Framework component of Oracle Siebel CRM (subcomponent: SWSE Server
    Infrastructure). Supported versions that are affected are 8.1.1, 8.2.2 and 15.0. Difficult to exploit
    vulnerability allows successful unauthenticated network attacks via HTTPS. Successful attack of this
    vulnerability can result in unauthorized update, insert or delete access to some Siebel UI Framework
    accessible data. (CVE-2015-2587)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # http://www.oracle.com/technetwork/topics/security/cpujul2015-2367936.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d18c2a85");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2015 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-2612");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/14");
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
  { 'min_version' : '8.1.1', 'fixed_version' : '8.1.1.15.1' },
  { 'min_version' : '8.2.2', 'fixed_version' : '8.2.2.15.1' },
  { 'min_version' : '15', 'fixed_version' : '15.1' },
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
