#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(212763);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/23");

  script_cve_id("CVE-2024-11639", "CVE-2024-11772", "CVE-2024-11773");
  script_xref(name:"IAVA", value:"2024-A-0799");

  script_name(english:"Ivanti Endpoint Manager Cloud Services Appliance < 5.0.3 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The instance of Ivanti Endpoint Manager Cloud Services Appliance running on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Ivanti Endpoint Manager Cloud Services Appliance running on the remote host is prior to 5.0.3. 
It is, therefore, affected by multiple vulnerabilities:

  - An authentication bypass in the admin web console of Ivanti CSA before 5.0.3 allows a remote unauthenticated 
    attacker to gain administrative access (CVE-2024-11639)

  - Command injection in the admin web console of Ivanti CSA before version 5.0.3 allows a remote authenticated attacker 
    with admin privileges to achieve remote code execution. (CVE-2024-11772)
  	
  - SQL injection in the admin web console of Ivanti CSA before version 5.0.3 allows a remote authenticated attacker 
    with admin privileges to run arbitrary SQL statements. (CVE-2024-11773)

Note that Nessus has not tested for these issues but has instead relied only on the service's self-reported version
number.");
  # https://forums.ivanti.com/s/article/Security-Advisory-Ivanti-Cloud-Services-Application-CSA-CVE-2024-11639-CVE-2024-11772-CVE-2024-11773?language=en_US
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e3786c69");
  script_set_attribute(attribute:"solution", value:
"Update to Ivanti Endpoint Manager Cloud Services Appliance 5.0.3 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-11639");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/12/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/12/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ivanti:endpoint_manager_cloud_services_appliance");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  { 'fixed_version':'5.0.3.0' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
