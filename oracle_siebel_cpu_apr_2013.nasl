#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(212367);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/11");

  script_cve_id(
    "CVE-2013-0416",
    "CVE-2013-1510",
    "CVE-2013-1543",
    "CVE-2013-1551",
    "CVE-2013-2398",
    "CVE-2013-2399",
    "CVE-2013-2403",
    "CVE-2013-2413"
  );

  script_name(english:"Oracle Siebel CRM (April 2013 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The versions of Oracle Siebel CRM installed on the remote host are affected by multiple vulnerabilities as referenced in
the April 2013 CPU advisory.

  - Vulnerability in the Siebel Enterprise Application Integration component of Oracle Siebel CRM
    (subcomponent: Web Services). Supported versions that are affected are 8.1.1 and 8.2.2. Difficult to
    exploit vulnerability allows successful authenticated network attacks via HTTP. Successful attack of this
    vulnerability can result in unauthorized update, insert or delete access to some Siebel Enterprise
    Application Integration accessible data as well as read access to a subset of Siebel Enterprise
    Application Integration accessible data. (CVE-2013-2413)

  - Vulnerability in the Siebel Enterprise Application Integration component of Oracle Siebel CRM
    (subcomponent: Web Services). Supported versions that are affected are 8.1.1 and 8.2.2. Difficult to
    exploit vulnerability allows successful authenticated network attacks via HTTP. Successful attack of this
    vulnerability can result in unauthorized read access to a subset of Siebel Enterprise Application
    Integration accessible data. (CVE-2013-2403)

  - Vulnerability in the Siebel Call Center component of Oracle Siebel CRM (subcomponent: Email - COMM Server
    Components). Supported versions that are affected are 8.1.1 and 8.2.2. Easily exploitable vulnerability
    allows successful authenticated network attacks via HTTP. Successful attack of this vulnerability can
    result in unauthorized read access to a subset of Siebel Call Center accessible data. (CVE-2013-2399)

  - Vulnerability in the Siebel UI Framework component of Oracle Siebel CRM (subcomponent: Open UI Client ).
    Supported versions that are affected are 8.1.1 and 8.2.2. Difficult to exploit vulnerability allows
    successful authenticated network attacks via HTTP. Successful attack of this vulnerability can result in
    unauthorized update, insert or delete access to some Siebel UI Framework accessible data as well as read
    access to a subset of Siebel UI Framework accessible data and ability to cause a partial denial of service
    (partial DOS) of Siebel UI Framework. (CVE-2013-2398)

  - Vulnerability in the Siebel Enterprise Application Integration component of Oracle Siebel CRM
    (subcomponent: Integration Business Services). Supported versions that are affected are 8.1.1 and 8.2.2.
    Difficult to exploit vulnerability allows successful authenticated network attacks via HTTP. Successful
    attack of this vulnerability can result in unauthorized update, insert or delete access to some Siebel
    Enterprise Application Integration accessible data as well as read access to a subset of Siebel Enterprise
    Application Integration accessible data and ability to cause a partial denial of service (partial DOS) of
    Siebel Enterprise Application Integration. (CVE-2013-1551)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # http://www.oracle.com/technetwork/topics/security/cpuapr2013-1899555.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?028971b4");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2013 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-2398");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2013-2399");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/04/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/16");
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
  { 'min_version' : '8.1.1', 'fixed_version' : '8.1.1.10' },
  { 'min_version' : '8.2.2', 'fixed_version' : '8.2.2.3' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
