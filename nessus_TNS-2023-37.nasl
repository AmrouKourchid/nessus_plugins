#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(184164);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/12/06");

  script_cve_id("CVE-2023-4807", "CVE-2023-5847", "CVE-2023-45853");
  script_xref(name:"IAVA", value:"2023-A-0606-S");

  script_name(english:"Tenable Nessus < 10.6.2 Multiple Vulnerabilities (TNS-2023-37)");

  script_set_attribute(attribute:"synopsis", value:
"An instance of Nessus installed on the remote system is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Tenable Nessus application running on the remote host is prior to 10.6.2. It
is, therefore, affected by multiple vulnerabilities as referenced in the TNS-2023-37 advisory.

  - Nessus leverages third-party software to help provide underlying functionality. Several of the third-party
    components (OpenSSL, zlib) were found to contain vulnerabilities, and updated versions have been made
    available by the providers.Out of caution and in line with best practice, Tenable has opted to upgrade
    these components to address the potential impact of the issues. Nessus 10.6.2 updates OpenSSL to version
    3.0.12, and zlib fixes have been applied to address the identified vulnerabilities.Additionally, one other
    vulnerability was discovered, reported and fixed:Under certain conditions, a low privileged attacker could
    load a specially crafted file during installation or upgrade to escalate privileges on Windows and Linux
    hosts. - CVE-2023-5847 Tenable has released Nessus 10.6.2 to address these issues. The installation files
    can be obtained from the Tenable Downloads Portal (https://www.tenable.com/downloads/nessus).
    (CVE-2023-45853, CVE-2023-4807, CVE-2023-5847)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/TNS-2023-37");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Tenable Nessus 10.6.2 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score based on analysis of the vendor advisory.");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/09/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/01");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:nessus");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nessus_detect.nasl", "nessus_installed_win.nbin", "nessus_installed_linux.nbin", "macos_nessus_installed.nbin");
  script_require_keys("installed_sw/Tenable Nessus");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::combined_get_app_info(app:'Tenable Nessus');

vcf::check_granularity(app_info:app_info, sig_segments:3);

var constraints = [
  { 'fixed_version' : '10.6.2' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
