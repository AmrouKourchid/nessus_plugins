#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(212765);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/23");

  script_cve_id("CVE-2024-11633", "CVE-2024-9844");
  script_xref(name:"IAVA", value:"2024-A-0800-S");

  script_name(english:"Pulse Connect Secure < 22.7R2.3 Multiple vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"Pulse Connect Secure installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Pulse Connect Secure installed on the remote host is prior to 22.7R2.3. It is, therefore, affected by 
multiple vulnerabilities.

- A heap-based buffer overflow in IPsec of Ivanti Connect Secure before version 22.7R2.3 allows a remote 
  unauthenticated attacker to cause a denial of service. (CVE-2024-37377)

- Command injection in Ivanti Connect Secure before version 22.7R2.3 and Ivanti Policy Secure allows a remote 
  authenticated attacker with admin privileges to achieve remote code (CVE-2024-11634)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://forums.ivanti.com/s/article/December-2024-Security-Advisory-Ivanti-Connect-Secure-ICS-and-Ivanti-Policy-Secure-IPS-Multiple-CVEs?language=en_US
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7e5dfedb");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Pulse Connect Secure 22.7R2.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-9844");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/12/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/12/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:pulsesecure:pulse_secure_desktop_client");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("pulse_connect_secure_detect.nbin");
  script_require_keys("installed_sw/Pulse Connect Secure");

  exit(0);
}

include('http.inc');
include('vcf.inc');
include('vcf_extras.inc');

var port = get_http_port(default:443, embedded:TRUE);
var app_info = vcf::pulse_connect_secure::get_app_info(app:'Pulse Connect Secure', port:port, full_version:TRUE, webapp:TRUE);

var constraints = [
  {'fixed_version':'22.7.2.3431', 'fixed_display':'22.7R2.3 (Build 3431)'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
