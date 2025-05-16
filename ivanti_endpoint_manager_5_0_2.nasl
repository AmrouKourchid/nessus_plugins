#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(208266);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/13");

  script_cve_id("CVE-2024-9379", "CVE-2024-9380", "CVE-2024-9381");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/10/30");
  script_xref(name:"IAVA", value:"2024-A-0636-S");

  script_name(english:"Ivanti Endpoint Manager Cloud Services Appliance < 5.0.2 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The instance of Ivanti Endpoint Manager Cloud Services Appliance running on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Ivanti Endpoint Manager Cloud Services Appliance running on the remote host is prior to 5.0.2. 
It is, therefore, affected by multiple vulnerabilities:

  - An OS command injection vulnerability in the admin web console of Ivanti CSA
    before version 5.0.2 allows a remote authenticated attacker with admin
    privileges to obtain remote code execution. (CVE-2024-9380)

  - Path traversal in Ivanti CSA before version 5.0.2 allows a remote
    authenticated attacker with admin privileges to bypass restrictions.
    (CVE-2024-9381)

  - SQL injection in the admin web console of Ivanti CSA before version 5.0.2
    allows a remote authenticated attacker with admin privileges to run
    arbitrary SQL statements.	(CVE-2024-9379)

Note that Nessus has not tested for these issues but has instead relied only on the service's self-reported version
number.");
  # https://forums.ivanti.com/s/article/Security-Advisory-Ivanti-CSA-Cloud-Services-Appliance-CVE-2024-9379-CVE-2024-9380-CVE-2024-9381?language=en_US
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ed15bc0b");
  script_set_attribute(attribute:"solution", value:
"Update to Ivanti Endpoint Manager Cloud Services Appliance 5.0.2 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-9381");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(22, 77, 89);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ivanti:endpoint_manager_cloud_services_appliance");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ivanti_endpoint_manager_csa_web_detect.nbin");
  script_require_keys("installed_sw/Ivanti Endpoint Manager Cloud Services Appliance");
  script_require_ports("Services/www", 443);

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var port = get_http_port(default:443);
var app_info = vcf::ivanti_csa::get_app_info(app:'Ivanti Endpoint Manager Cloud Services Appliance', port:port);

var constraints = [
  { 'fixed_version':'5.0.2.0' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
