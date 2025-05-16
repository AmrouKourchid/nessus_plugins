#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(216316);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/21");

  script_cve_id("CVE-2024-38657", "CVE-2024-10644");
  script_xref(name:"IAVA", value:"2025-A-0100");

  script_name(english:"Ivanti Connect Secure 22.x <  22.7R2.4 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A VPN solution installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Ivanti Connect Secure installed on the remote host is prior to  22.7R2.4. It is, therefore, affected 
by multiple vulnerabilities in the admin portal:

  - External control of a file name in Ivanti Connect Secure before version 22.7R2.4 
    and Ivanti Policy Secure before version 22.7R1.3 allows a remote authenticated 
    attacker with admin privileges to write arbitrary files. (CVE-2024-38657)
  
  - Code injection in Ivanti Connect Secure before version 22.7R2.4 and Ivanti Policy Secure 
    before version 22.7R1.3 allows a remote authenticated attacker with admin privileges to 
    achieve remote code execution. (CVE-2024-10644)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://forums.ivanti.com/s/article/February-Security-Advisory-Ivanti-Connect-Secure-ICS-Ivanti-Policy-Secure-IPS-and-Ivanti-Secure-Access-Client-ISAC-Multiple-CVEs
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?76697fcf");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Ivanti Connect Secure 22.7R2.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-38657");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(73, 94);

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/02/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/02/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ivanti:connect_secure");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:pulse_secure:connect_secure");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("pulse_connect_secure_detect.nbin");
  script_require_keys("installed_sw/Pulse Connect Secure");

  exit(0);
}

include('vcf_extras.inc');

var port = get_http_port(default:443, embedded:TRUE);
var app_info = vcf::pulse_connect_secure::get_app_info(app:'Pulse Connect Secure', port:port, full_version:TRUE, webapp:TRUE);

var constraints = [
  {'min_version':'22.0', 'fixed_version':'22.7.2.3597',   'fixed_display':'22.7R2.4 (Build 3597)'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
