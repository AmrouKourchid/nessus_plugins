#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(187053);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/12/27");

  script_cve_id("CVE-2022-31702", "CVE-2022-31703");
  script_xref(name:"IAVA", value:"2023-A-0057-S");

  script_name(english:"VMware vRealize Network Insight (vRNI) Multiple Vulnerabilities (VMSA-2022-0031)");

  script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the instance of VMware vRealize Network Insight running on the remote web
server is affected by multiple vulnerabilities:

  - vRealize Network Insight (vRNI) contains a command injection vulnerability present in the vRNI REST API. A 
    malicious actor with network access to the vRNI REST API can execute commands without authentication.. 
    (CVE-2022-31702)

  - The vRealize Log Insight contains a Directory Traversal Vulnerability. An unauthenticated, malicious actor can 
    inject files into the operating system of an impacted appliance which can result in remote code execution. 
    (CVE-2022-31703)
  
Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2022-0031.html");
  # https://www.vmware.com/security/advisories/VMSA-2022-0031.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?87c9ed77");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware vRealize Network Insight 6.2.0.1670436787, 6.3.0.1670421532, 6.4.0.1670379658, 6.5.1.1670383888,
6.6.0.1670381875, 6.7.0.1670340571 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-31702");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/12/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/12/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vrealize_network_insight");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:vmware:aria_operations_for_networks");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_aria_operations_for_networks_web_detect.nbin");
  script_require_keys("installed_sw/VMware vRealize Network Insight");
  script_require_ports("Services/www", 443);

  exit(0);
}

include('vcf.inc');
include('http.inc');

var port = get_http_port(default:443);

var app_info = vcf::get_app_info(app:'VMware vRealize Network Insight', port:port, webapp:TRUE);

var constraints = [
  {'min_version':'6.2', 'fixed_version':'6.2.0.1670436787', 'fixed_display': '6.2 Patch 7'},
  {'min_version':'6.3', 'fixed_version':'6.3.0.1670421532', 'fixed_display': '6.3 Patch 4'},
  {'min_version':'6.4', 'fixed_version':'6.4.0.1670379658', 'fixed_display': '6.4 Patch 8'},
  {'min_version':'6.5', 'fixed_version':'6.5.1.1670383888', 'fixed_display': '6.5 Patch 5'},
  {'min_version':'6.6', 'fixed_version':'6.6.0.1670381875', 'fixed_display': '6.6 Patch 4'},
  {'min_version':'6.7', 'fixed_version':'6.7.0.1670340571', 'fixed_display': '6.7 Patch 4'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
