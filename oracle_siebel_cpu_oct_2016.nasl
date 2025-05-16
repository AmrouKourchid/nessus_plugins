#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(212379);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/11");

  script_cve_id("CVE-2016-5534", "CVE-2016-5560");

  script_name(english:"Oracle Siebel CRM < 16.5 (October 2016 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The versions of Oracle Siebel CRM installed on the remote host are affected by multiple vulnerabilities as referenced in
the October 2016 CPU advisory.

  - Vulnerability in the Siebel Apps - Customer Order Management component of Oracle Siebel CRM (subcomponent:
    Customizable Prod/Configurator). The supported version that is affected is 16.4 and below. Easily
    exploitable vulnerability allows low privileged attacker with network access via HTTP to compromise Siebel
    Apps - Customer Order Management. Successful attacks of this vulnerability can result in unauthorized 
    access to critical data or complete access to all Siebel Apps - Customer Order Management accessible data.
    (CVE-2016-5534)

  - Vulnerability in the Siebel UI Framework component of Oracle Siebel CRM (subcomponent: OpenUI). The
    supported version that is affected is 16.4 and below. Easily exploitable vulnerability allows low 
    privileged attacker with network access via HTTP to compromise Siebel UI Framework. Successful attacks of 
    this vulnerability can result in unauthorized update, insert or delete access to some of Siebel UI 
    Framework accessible data as well as unauthorized read access to a subset of Siebel UI Framework 
    accessible data. (CVE-2016-5560)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # http://www.oracle.com/technetwork/security-advisory/cpuoct2016-2881722.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bac902d5");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2016 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-5560");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2016-5534");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/18");
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
  { 'fixed_version' : '16.5' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
