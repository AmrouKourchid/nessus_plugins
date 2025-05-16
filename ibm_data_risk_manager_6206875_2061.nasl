#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(181415);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/09/14");

  script_cve_id("CVE-2020-4427", "CVE-2020-4429");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");

  script_name(english:"IBM Data Risk Manager 2.0.1 <= 2.0.6.1 Multiple Vulnerabilities (6206875)");

  script_set_attribute(attribute:"synopsis", value:
"The remote virtual appliance is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of IBM Data Risk Manager installed on the remote host is between 2.0.1 and 2.0.6.1. It is, therefore,
affected by multiple vulnerabilities:

  -  IBM Data Risk Manager could allow a remote attacker to bypass security restrictions when configured with
  SAML authentication. By sending a specially crafted HTTP request, an attacker could exploit this 
  vulnerability to bypass the authentication process and gain full administrative access to the system.
  (CVE-2020-4427)

  - IBM Data Risk Manager contains a default password for an IDRM administrative account. A remote attacker
  could exploit this vulnerability to login and execute arbitrary code on the system with root privileges.
  (CVE-2020-4429)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/6206875");
  script_set_attribute(attribute:"see_also", value:"https://exchange.xforce.ibmcloud.com/vulnerabilities/180532");
  script_set_attribute(attribute:"see_also", value:"https://exchange.xforce.ibmcloud.com/vulnerabilities/180534");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM Data Risk Manager 2.0.6.2 Fixpack or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-4429");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'IBM Data Risk Manager a3user Default Password');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/05");
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
  { 'min_version':'2.0.1', 'max_version':'2.0.6.1', 'fixed_version': '2.0.6.2', 'fixed_display':'2.0.6.2 Fixpack' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);