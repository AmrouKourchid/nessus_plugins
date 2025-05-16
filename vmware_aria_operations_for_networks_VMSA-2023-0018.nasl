#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(180411);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/10/25");

  script_cve_id("CVE-2023-34039", "CVE-2023-20890");

  script_name(english:"VMWare Aria Operations for Networks Multiple Vulnerabilities (VMSA-2023-0018)");

  script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the instance of VMWare Aria Operations for Networks running on the remote web
server is 6.x < 6.2.0.1688977536, 6.3.x < 6.3.0.1688986302, 6.4.x < 6.4.0.1689079386, 6.5.x < 6.5.1.1688974096, 6.6.x <
6.6.0.1688979729, 6.7.x < 6.7.0.1688972173, 6.8.x < 6.8.0.1688989059, 6.9.x < 6.9.0.1688995771, or 6.10.x <
6.10.0.1692934256. It is, therefore, affected by multiple vulnerabilities:

  - Aria Operations for Networks contains an Authentication Bypass vulnerability due to a lack of unique cryptographic
    key generation. A malicious actor with network access to Aria Operations for Networks could bypass SSH
    authentication to gain access to the Aria Operations for Networks CLI. (CVE-2023-34039)

  - Aria Operations for Networks contains an arbitrary file write vulnerability. An authenticated malicious actor with
    administrative access to VMware Aria Operations for Networks can write files to arbitrary locations resulting in
    remote code execution. (CVE-2023-20890)
  
Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2023-0018.html");
  script_set_attribute(attribute:"see_also", value:"https://kb.vmware.com/s/article/94152");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMWare Aria Operations for Networks 6.2.0.1688977536, 6.3.0.1688986302, 6.4.0.1689079386, 6.5.1.1688974096,
6.6.0.1688979729, 6.7.0.1688972173, 6.8.0.1688989059, 6.9.0.1688995771, or 6.10.0.1692934256 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-34039");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'VMWare Aria Operations for Networks (vRealize Network Insight) SSH Private Key Exposure');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/07/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/07/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/08/31");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vrealize_network_insight");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:vmware:aria_operations_for_networks");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_aria_operations_for_networks_web_detect.nbin");
  script_require_keys("installed_sw/VMware Aria Operations for Networks");
  script_require_ports("Services/www", 443);

  exit(0);
}

include('vcf.inc');
include('http.inc');

var port = get_http_port(default:443);

var app_info = vcf::get_app_info(app:'VMware Aria Operations for Networks', port:port, webapp:TRUE);

var constraints = [
  {'min_version':'6.0', 'fixed_version':'6.2.0.1688977536'},
  {'min_version':'6.3', 'fixed_version':'6.3.0.1688986302'},
  {'min_version':'6.4', 'fixed_version':'6.4.0.1689079386'},
  {'min_version':'6.5', 'fixed_version':'6.5.1.1688974096'},
  {'min_version':'6.6', 'fixed_version':'6.6.0.1688979729'},
  {'min_version':'6.7', 'fixed_version':'6.7.0.1688972173'},
  {'min_version':'6.8', 'fixed_version':'6.8.0.1688989059'},
  {'min_version':'6.9', 'fixed_version':'6.9.0.1688995771'},
  {'min_version':'6.10', 'fixed_version':'6.10.0.1692934256'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);