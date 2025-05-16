#%NASL_MIN_LEVEL 80900
##
# (c) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(216315);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/19");

  script_cve_id(
    "CVE-2024-38657",
    "CVE-2024-10644",
    "CVE-2024-12058",
    "CVE-2024-13830",
    "CVE-2024-13842",
    "CVE-2024-13843"
  );
  script_xref(name:"IAVA", value:"2025-A-0100");

  script_name(english:"Ivanti Policy Secure 22.x < 22.7R1.3 RCE");

  script_set_attribute(attribute:"synopsis", value:
"A NAC solution installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Ivanti Policy Secure installed on the remote host is prior to 22.7R1.3. It is, therefore, 
affected by multiple vulnerabilities in the admin portal:

  - External control of a file name in Ivanti Connect Secure before version 22.7R2.4 
    and Ivanti Policy Secure before version 22.7R1.3 allows a remote authenticated 
    attacker with admin privileges to write arbitrary files. (CVE-2024-38657)
  
  - Code injection in Ivanti Connect Secure before version 22.7R2.4 and Ivanti Policy Secure 
    before version 22.7R1.3 allows a remote authenticated attacker with admin privileges to 
    achieve remote code execution. (CVE-2024-10644)

  - Cleartext storage of information in Ivanti Connect Secure before version 22.7R2.6 and Ivanti 
    Policy Secure before version 22.7R1.3 allows a local unauthenticated attacker to read 
    sensitive data. (CVE-2024-13843)

  - A hardcoded key in Ivanti Connect Secure before version 22.7R2.3 and Ivanti Policy Secure 
    before version 22.7R1.3 allows a local unauthenticated attacker to read sensitive data.
    (CVE-2024-13842)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://forums.ivanti.com/s/article/February-Security-Advisory-Ivanti-Connect-Secure-ICS-Ivanti-Policy-Secure-IPS-and-Ivanti-Secure-Access-Client-ISAC-Multiple-CVEs
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?76697fcf");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Ivanti Pulse Policy Secure 22.7R1.3 (Build 1737) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-38657");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-13830");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(73, 79, 94, 312, 321);

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/02/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/02/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ivanti:policy_secure");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:pulse_secure:pulse_policy_secure");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("pulse_policy_secure_detect.nbin");
  script_require_keys("installed_sw/Pulse Policy Secure");

  exit(0);
}

include('vcf.inc');
include('http.inc');

var port = get_http_port(default:443);
var app_info = vcf::get_app_info(app:'Pulse Policy Secure', port:port);

var constraints = [
  {'fixed_version':'22.7.1.1737', 'fixed_display': '22.7R1.3 (Build 1737)'} 
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);

