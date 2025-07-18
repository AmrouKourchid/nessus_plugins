#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(212378);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/11");

  script_cve_id(
    "CVE-2016-3450",
    "CVE-2016-3469",
    "CVE-2016-3472",
    "CVE-2016-5450",
    "CVE-2016-5451",
    "CVE-2016-5456",
    "CVE-2016-5459",
    "CVE-2016-5460",
    "CVE-2016-5461",
    "CVE-2016-5462",
    "CVE-2016-5463",
    "CVE-2016-5464",
    "CVE-2016-5466",
    "CVE-2016-5468"
  );

  script_name(english:"Oracle Siebel CRM (July 2016 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The versions of Oracle Siebel CRM installed on the remote host are affected by multiple vulnerabilities as referenced in
the July 2016 CPU advisory.

  - Vulnerability in the Siebel UI Framework component of Oracle Siebel CRM (subcomponent: EAI). Supported
    versions that are affected are 8.1.1, 8.2.2, IP2014, IP2015 and IP2016. Easily exploitable vulnerability
    allows low privileged attacker with network access via HTTP to compromise Siebel UI Framework. Successful
    attacks of this vulnerability can result in unauthorized creation, deletion or modification access to
    critical data or all Siebel UI Framework accessible data as well as unauthorized access to critical data
    or complete access to all Siebel UI Framework accessible data. (CVE-2016-5451)

  - Vulnerability in the Siebel Core - Server Framework component of Oracle Siebel CRM (subcomponent: Object
    Manager). Supported versions that are affected are 8.1.1, 8.2.2, IP2014, IP2015 and IP2016. Easily
    exploitable vulnerability allows low privileged attacker with network access via HTTP to compromise Siebel
    Core - Server Framework. Successful attacks of this vulnerability can result in unauthorized access to
    critical data or complete access to all Siebel Core - Server Framework accessible data. (CVE-2016-5461)

  - Vulnerability in the Siebel Engineering - Installer and Deployment component of Oracle Siebel CRM
    (subcomponent: Web Server). Supported versions that are affected are 8.1.1, 8.2.2, IP2014, IP2015 and
    IP2016. Easily exploitable vulnerability allows low privileged attacker with network access via HTTP to
    compromise Siebel Engineering - Installer and Deployment. Successful attacks require human interaction
    from a person other than the attacker. Successful attacks of this vulnerability can result in unauthorized
    access to critical data or complete access to all Siebel Engineering - Installer and Deployment accessible
    data. (CVE-2016-3472)

  - Vulnerability in the Siebel UI Framework component of Oracle Siebel CRM (subcomponent: EAI). Supported
    versions that are affected are 8.1.1, 8.2.2, IP2014, IP2015 and IP2016. Easily exploitable vulnerability
    allows low privileged attacker with network access via HTTP to compromise Siebel UI Framework. Successful
    attacks of this vulnerability can result in unauthorized update, insert or delete access to some of Siebel
    UI Framework accessible data as well as unauthorized read access to a subset of Siebel UI Framework
    accessible data. (CVE-2016-5468)

  - Vulnerability in the Siebel Core - Server Framework component of Oracle Siebel CRM (subcomponent:
    Services). Supported versions that are affected are 8.1.1, 8.2.2, IP2014, IP2015 and IP2016. Difficult to
    exploit vulnerability allows low privileged attacker with network access via HTTP to compromise Siebel
    Core - Server Framework. Successful attacks of this vulnerability can result in unauthorized access to
    critical data or complete access to all Siebel Core - Server Framework accessible data. (CVE-2016-5456)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # http://www.oracle.com/ocom/groups/public/@otn/documents/webcontent/3089849.xml
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?42cde00c");
  # http://www.oracle.com/technetwork/security-advisory/cpujul2016-2881720.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?453b5f8c");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2016 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-5456");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2016-5451");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/19");
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
  { 'min_version' : '8.1.1', 'fixed_version' : '8.1.1.16.4' },
  { 'min_version' : '8.2.2', 'fixed_version' : '8.2.2.16.4' },
  { 'min_version' : '14', 'fixed_version' : '16.4' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
