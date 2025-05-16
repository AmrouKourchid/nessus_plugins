#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(212128);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/16");

  script_cve_id(
    "CVE-2023-49582",
    "CVE-2024-4603",
    "CVE-2024-4741",
    "CVE-2024-5458",
    "CVE-2024-5535",
    "CVE-2024-5585",
    "CVE-2024-6119",
    "CVE-2024-12174"
  );
  script_xref(name:"IAVA", value:"2024-A-0820");

  script_name(english:"Tenable Security Center < 6.5.0 Multiple Vulnerabilities (TNS-2024-19)");

  script_set_attribute(attribute:"synopsis", value:
"An instance of Security Center installed on the remote system is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Tenable Security Center running on the remote host is prior to 6.5.0. It is,
therefore, affected by multiple vulnerabilities as referenced in the TNS-2024-19 advisory.

  - Security Center leverages third-party software to help provide underlying functionality. Several of the
    third-party components (OpenSSL, PHP, Apache Portable Runtime) were found to contain vulnerabilities, and
    updated versions have been made available by the providers.Out of caution and in line with best practice,
    Tenable has opted to upgrade these components to address the potential impact of the issues. Security
    Center 6.5.0 updates OpenSSL to version 3.0.15, PHP to version 8.2.24 and Apache Portable Runtime to
    version 1.7.5 to address the identified vulnerabilities.Additionally, one separate vulnerability was
    discovered, reported and fixed:An Improper Certificate Validation vulnerability exists in Tenable Security
    Center where an authenticated, privileged attacker could intercept email messages sent from Security
    Center via a rogue SMTP server. - CVE-2024-12174 Tenable has released Security Center 6.5.0 to address
    these issues. The installation files can be obtained from the Tenable Downloads Portal:
    https://www.tenable.com/downloads/security-center (CVE-2023-49582, CVE-2024-12174, CVE-2024-4603,
    CVE-2024-4741, CVE-2024-5458, CVE-2024-5535, CVE-2024-5585, CVE-2024-6119)

  - An Improper Certificate Validation vulnerability exists in Tenable Security Center where an authenticated,
    privileged attacker could intercept email messages sent from Security Center via a rogue SMTP server.
    (CVE-2024-12174)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://docs.tenable.com/release-notes/Content/security-center/2024.htm#650
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?65e9efbe");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/TNS-2024-19");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Tenable Security Center 6.5.0 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-5535");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-5585");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/12/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/06");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:security_center");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("securitycenter_installed.nbin", "securitycenter_detect.nbin");
  script_require_ports("installed_sw/SecurityCenter");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::tenable_sc::get_app_info();

var constraints = [
  { 'max_version' : '6.4.5', 'fixed_display' : 'Upgrade to 6.5.0 or later' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
