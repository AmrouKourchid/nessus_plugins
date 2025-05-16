#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(211455);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/13");

  script_cve_id(
    "CVE-2024-8495",
    "CVE-2024-11004",
    "CVE-2024-11005",
    "CVE-2024-11006",
    "CVE-2024-11007",
    "CVE-2024-38649",
    "CVE-2024-38655",
    "CVE-2024-38656"
  );
  script_xref(name:"IAVA", value:"2024-A-0736-S");

  script_name(english:"Pulse Connect Secure < 22.7R2.1 Multiple Vulnerabilities (000096001)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The version of Pulse Connect Secure installed on the remote host is prior to 22.7R2.1. It is, therefore, affected by
multiple vulnerabilities as referenced in the 000096001 advisory.

  - Argument injection in Ivanti Connect Secure before version 22.7R2.1 and Ivanti Policy Secure before
    version 22.7R1.1 allows a remote authenticated attacker with admin privileges to achieve remote code
    execution. (CVE-2024-38655)

  - Command injection in Ivanti Connect Secure before version 22.7R2.1 and Ivanti Policy Secure before version
    22.7R1.1 allows a remote authenticated attacker with admin privileges to achieve remote code execution.
    (CVE-2024-11005, CVE-2024-11006, CVE-2024-11007)

  - Reflected XSS in Ivanti Connect Secure before version 22.7R2.1 and Ivanti Policy Secure before version
    22.7R1.1 allows a remote unauthenticated attacker to obtain admin privileges. User interaction is
    required. (CVE-2024-11004)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://forums.ivanti.com/s/article/Security-Advisory-Ivanti-Connect-Secure-ICS-Ivanti-Policy-Secure-IPS-Ivanti-Secure-Access-Client-ISAC-Multiple-CVEs?language=en_US
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d7626e0b");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Pulse Connect Secure version 22.7R2.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-38655");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-11007");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/11/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:pulsesecure:pulse_connect_secure");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("pulse_connect_secure_detect.nbin");
  script_require_keys("installed_sw/Pulse Connect Secure");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::combined_get_app_info(app:'Pulse Connect Secure');

var constraints = [
  { 'fixed_version' : '22.7.2.3191', 'fixed_display' : '22.7R2.1' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE,
    flags:{'xss':TRUE}
);
