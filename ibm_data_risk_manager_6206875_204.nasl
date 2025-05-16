#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(181416);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/09/14");

  script_cve_id("CVE-2020-4428", "CVE-2020-4430");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");

  script_name(english:"IBM Data Risk Manager 2.0.1 <= 2.0.4 Multiple Vulnerabilities (6206875)");

  script_set_attribute(attribute:"synopsis", value:
"The remote virtual appliance is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of IBM Data Risk Manager installed on the remote host is between 2.0.1 and 2.0.4. It is, therefore,
affected by multiple vulnerabilities:

  - IBM Data Risk Manager 2.0.1, 2.0.2, 2.0.3, and 2.0.4 could allow a remote authenticated attacker to
  execute arbitrary commands on the system. IBM X-Force ID: 180533. (CVE-2020-4428)

  - IBM Data Risk Manager 2.0.1, 2.0.2, 2.0.3, and 2.0.4 could allow a remote authenticated attacker to
  traverse directories on the system. An attacker could send a specially-crafted URL request to download
  arbitrary files from the system. IBM X-Force ID: 180535. (CVE-2020-4430)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/6206875");
  script_set_attribute(attribute:"see_also", value:"https://exchange.xforce.ibmcloud.com/vulnerabilities/180533");
  script_set_attribute(attribute:"see_also", value:"https://exchange.xforce.ibmcloud.com/vulnerabilities/180535");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM Data Risk Manager 2.0.4.1 Fixpack or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-4428");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'IBM Data Risk Manager Unauthenticated Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/14");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:data_risk_manager");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ibm_data_risk_manager_installed.nbin", "ibm_data_risk_manager_web_detect.nbin");
  script_require_keys("installed_sw/IBM Data Risk Manager");

  exit(0);
}

include('vcf.inc');
include('http.inc');

var app = 'IBM Data Risk Manager';
var app_info = vcf::combined_get_app_info(app:app);

var constraints = [
  { 'min_version':'2.0.1', 'max_version':'2.0.4', 'fixed_version': '2.0.4.1', 'fixed_display':'2.0.4.1 Fixpack' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);