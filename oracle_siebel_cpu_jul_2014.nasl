#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(212370);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/12");

  script_cve_id(
    "CVE-2014-2485",
    "CVE-2014-2491",
    "CVE-2014-4205",
    "CVE-2014-4230",
    "CVE-2014-4231",
    "CVE-2014-4250"
  );

  script_name(english:"Oracle Siebel CRM (July 2014 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The versions of Oracle Siebel CRM installed on the remote host are affected by multiple vulnerabilities as referenced in
the July 2014 CPU advisory.

  - Vulnerability in the Siebel Travel & Transportation component of Oracle Siebel CRM (subcomponent: Diary).
  Supported versions that are affected are 8.1.1 and 8.2.2. Difficult to exploit vulnerability allows 
  successful unauthenticated network attacks via HTTP. Successful attack of this vulnerability can result in
  unauthorized update, insert or delete access to some Siebel Travel & Transportation accessible data.

  - Vulnerability in the Siebel UI Framework component of Oracle Siebel CRM (subcomponent: Open_UI).
  Supported versions that are affected are 8.1.1 and 8.2.2. Difficult to exploit vulnerability allows
  successful unauthenticated network attacks via HTTP. Successful attack of this vulnerability can result in
  unauthorized update, insert or delete access to some Siebel UI Framework accessible data. (CVE-2014-4230)

  - Vulnerability in the Siebel UI Framework component of Oracle Siebel CRM (subcomponent: Portal Framework).
  Supported versions that are affected are 8.1.1 and 8.2.2. Difficult to exploit vulnerability allows 
  successful unauthenticated network attacks via HTTP. Successful attack of this vulnerability can result in 
  unauthorized update, insert or delete access to some Siebel UI Framework accessible data. (CVE-2014-2491) 

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujul2014.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2014 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-4231");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/07/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/15");
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
  { 'min_version' : '8.1.1', 'fixed_version' : '8.1.1.11.9' },
  { 'min_version' : '8.2.2', 'fixed_version' : '8.2.2.4.9' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
