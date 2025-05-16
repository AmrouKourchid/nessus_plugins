#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(211453);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/23");

  script_cve_id(
    "CVE-2024-9420",
    "CVE-2024-37400",
    "CVE-2024-47905",
    "CVE-2024-47906",
    "CVE-2024-47907",
    "CVE-2024-47909"
  );
  script_xref(name:"IAVA", value:"2024-A-0736-S");

  script_name(english:"Pulse Connect Secure < 22.7R2.3 Multiple Vulnerabilities (000096001)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The version of Pulse Connect Secure installed on the remote host is prior to 22.7R2.3. It is, therefore, affected by
multiple vulnerabilities as referenced in the 000096001 advisory.

  - An out of bounds read in Ivanti Connect Secure before version 22.7R2.3 allows a remote unauthenticated
    attacker to trigger an infinite loop, causing a denial of service. (CVE-2024-37400)

  - A use-after-free in Ivanti Connect Secure before version 22.7R2.3 and Ivanti Policy Secure before version
    22.7R1.2 allows a remote authenticated attacker to achieve remote code execution. (CVE-2024-9420)

  - Excessive binary privileges in Ivanti Connect Secure which affects versions 22.4R2 through 22.7R2.2
    inclusive within the R2 release line and Ivanti Policy Secure before version 22.7R1.2 allow a local
    authenticated attacker to escalate privileges. (CVE-2024-47906)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://forums.ivanti.com/s/article/Security-Advisory-Ivanti-Connect-Secure-ICS-Ivanti-Policy-Secure-IPS-Ivanti-Secure-Access-Client-ISAC-Multiple-CVEs
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a16fc73a");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Pulse Connect Secure version 22.7R2.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-9420");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/11/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:pulsesecure:pulse_connect_secure");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("pulse_connect_secure_detect.nbin");
  script_require_keys("installed_sw/Pulse Connect Secure");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::combined_get_app_info(app:'Pulse Connect Secure');

var constraints = [
  { 'fixed_version' : '22.7.2.3431', 'fixed_display' : '22.7R2.3' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
