#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(190219);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/12");

  script_cve_id(
    "CVE-2024-22237",
    "CVE-2024-22238",
    "CVE-2024-22239",
    "CVE-2024-22240",
    "CVE-2024-22241"
  );
  script_xref(name:"VMSA", value:"2024-0002");
  script_xref(name:"IAVA", value:"2024-A-0074");

  script_name(english:"VMWare Aria Operations for Networks 6.x < 6.12 Multiple Vulnerabilities (VMSA-2024-0002)");

  script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the instance of VMWare Aria Operations for Networks running on the remote web
server is 6.x < 6.12.0.1706185032. It is, therefore, affected by multiple vulnerabilities:

  - Aria Operations for Networks contains a local privilege escalation vulnerability. A console user with access
    to Aria Operations for Networks may exploit this vulnerability to escalate privileges to gain root access to 
    the system. (CVE-2024-22237, CVE-2024-22239)

  - Aria Operations for Networks contains a cross site scripting vulnerability. A malicious actor with admin 
    privileges may be able to inject malicious code into user profile configurations due to improper input 
    sanitization. (CVE-2024-22238)

  - Aria Operations for Networks contains a local file read vulnerability. A malicious actor with admin 
    privileges may exploit this vulnerability leading to unauthorized access to sensitive information. 
    (CVE-2024-22240)

  - Aria Operations for Networks contains a cross site scripting vulnerability. A malicious actor with admin 
    privileges can inject a malicious payload into the login banner and takeover the user account. (CVE-2024-22241)
  
Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.vmware.com/security/advisories/VMSA-2024-0002.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4706d766");
  script_set_attribute(attribute:"see_also", value:"https://kb.vmware.com/s/article/96450");
  # https://docs.vmware.com/en/VMware-Aria-Operations-for-Networks/services/rn/vmware-aria-operations-for-networks-release-notes/index.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2f273435");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMWare Aria Operations for Networks 6.12.0.1706185032 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-22239");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vrealize_network_insight");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:vmware:aria_operations_for_networks");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  {'min_version':'6.0', 'fixed_version':'6.12.0.1706185032'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);