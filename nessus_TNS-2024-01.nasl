#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(190097);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/13");

  script_cve_id("CVE-2024-0955", "CVE-2024-0971");
  script_xref(name:"IAVA", value:"2024-A-0072-S");

  script_name(english:"Tenable Nessus < 10.7.0 Multiple Vulnerabilities (TNS-2024-01)");

  script_set_attribute(attribute:"synopsis", value:
"An instance of Nessus installed on the remote system is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Tenable Nessus application running on the remote host is prior to 10.7.0. It
is, therefore, affected by multiple vulnerabilities as referenced in the TNS-2024-01 advisory.

  - A stored XSS vulnerability exists where an authenticated, remote attacker with administrator privileges
    on the Nessus application could alter Nessus proxy settings, which could lead to the execution of remote
    arbitrary scripts. (CVE-2024-0955)

  - A SQL injection vulnerability exists where an authenticated, low-privileged remote attacker could potentially
    alter scan DB content. (CVE-2024-0971)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/TNS-2024-01");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Tenable Nessus 10.7.0 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score based on an in-depth analysis by Tenable.");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_severity", value:"Medium");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/07");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:nessus");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nessus_detect.nasl", "nessus_installed_win.nbin", "nessus_installed_linux.nbin", "macos_nessus_installed.nbin");
  script_require_keys("installed_sw/Tenable Nessus");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::combined_get_app_info(app:'Tenable Nessus');

vcf::check_granularity(app_info:app_info, sig_segments:3);

var constraints = [
  { 'max_version' : '10.6.4', 'fixed_display' : '10.7.0' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING,
    flags:{'sqli':TRUE, 'xss':TRUE}
);
