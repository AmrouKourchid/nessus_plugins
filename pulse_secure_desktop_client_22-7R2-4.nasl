#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(212766);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/23");

  script_cve_id("CVE-2024-11633", "CVE-2024-9844");
  script_xref(name:"IAVA", value:"2024-A-0800-S");

  script_name(english:"Pulse Connect Secure < 22.7R2.4 multiple vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"Pulse Connect Secure installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Pulse Connect Secure installed on the remote host is prior to 22.7R2.4. It is, therefore, affected by 
multiple vulnerabilities.

- Insufficient server-side controls in Secure Application Manager of Ivanti Connect Secure before version
  22.7R2.4 allows a remote authenticated attacker to bypass restrictions. (CVE-2024-9844)

- Argument injection in Ivanti Connect Secure before version 22.7R2.4 allows a remote authenticated attacker with 
  admin privileges to achieve remote code execution (CVE-2024-11633)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://kb.pulsesecure.net/articles/Pulse_Secure_Article/Client-Side-Desync-Attack-Informational-Article/?kA13Z000000FsZz
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?da57d3b2");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Pulse Connect Secure 22.7R2.4 or later.");
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
  {'fixed_version':'22.7.2.3597', 'fixed_display':'22.7R2.4 (Build 3597)'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
