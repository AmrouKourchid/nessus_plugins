#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(212363);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/12");

  script_cve_id(
    "CVE-2012-1728",
    "CVE-2012-1731",
    "CVE-2012-1732",
    "CVE-2012-1742",
    "CVE-2012-1754",
    "CVE-2012-1760",
    "CVE-2012-1761"
  );

  script_name(english:"Oracle Siebel CRM (July 2012 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The versions of Oracle Siebel CRM installed on the remote host are affected by multiple vulnerabilities as referenced in
the July 2012 CPU advisory.

  - Vulnerability in the Siebel CRM component of Oracle Siebel CRM (subcomponent: UI Framework). Supported
    versions that are affected are 8.1.1 and 8.2.2. Difficult to exploit vulnerability allows successful
    unauthenticated network attacks via HTTP. Successful attack of this vulnerability can result in
    unauthorized update, insert or delete access to some Siebel CRM accessible data. (CVE-2012-1761)

  - Vulnerability in the Siebel CRM component of Oracle Siebel CRM (subcomponent: UI Framework). Supported
    versions that are affected are 8.1.1 and 8.2.2. Difficult to exploit vulnerability allows successful
    unauthenticated network attacks via HTTP. Successful attack of this vulnerability can result in
    unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of Siebel CRM.
    (CVE-2012-1760)

  - Vulnerability in the Siebel CRM component of Oracle Siebel CRM (subcomponent: UI Framework). Supported
    versions that are affected are 8.1.1 and 8.2.2. Easily exploitable vulnerability allows successful
    authenticated network attacks via HTTP. Successful attack of this vulnerability can result in unauthorized
    read access to a subset of Siebel CRM accessible data. (CVE-2012-1732, CVE-2012-1754)

  - Vulnerability in the Siebel CRM component of Oracle Siebel CRM (subcomponent: UI Framework). Supported
    versions that are affected are 8.1.1 and 8.2.2. Easily exploitable vulnerability allows successful
    unauthenticated network attacks via HTTP. Successful attack of this vulnerability can result in
    unauthorized ability to cause a partial denial of service (partial DOS) of Siebel CRM. (CVE-2012-1742)

  - Vulnerability in the Siebel CRM component of Oracle Siebel CRM (subcomponent: Web UI). Supported versions
    that are affected are 8.1.1 and 8.2.2. Difficult to exploit vulnerability allows successful
    unauthenticated network attacks via HTTP. Successful attack of this vulnerability can result in
    unauthorized update, insert or delete access to some Siebel CRM accessible data as well as read access to
    a subset of Siebel CRM accessible data and ability to cause a partial denial of service (partial DOS) of
    Siebel CRM. (CVE-2012-1731)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # http://www.oracle.com/ocom/groups/public/@otn/documents/webcontent/1695912.xml
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b3fb8291");
  # http://www.oracle.com/technetwork/topics/security/cpujul2012-392727.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bd39edea");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2012 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-1731");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/07/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/17");
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
  { 'min_version' : '8.1.1', 'fixed_version' : '8.1.1.8' },
  { 'min_version' : '8.2.2', 'fixed_version' : '8.2.2.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
