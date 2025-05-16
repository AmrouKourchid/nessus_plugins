#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(200260);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/02");

  script_cve_id(
    "CVE-2023-38709",
    "CVE-2024-1874",
    "CVE-2024-1891",
    "CVE-2024-3096",
    "CVE-2024-5759",
    "CVE-2024-24795",
    "CVE-2024-27316"
  );

  script_name(english:"Tenable Security Center < 6.4.0 Multiple Vulnerabilities (TNS-2024-10)");

  script_set_attribute(attribute:"synopsis", value:
"An instance of Security Center installed on the remote system is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Tenable Security Center running on the remote host is prior to 6.4.0. It is,
therefore, affected by multiple vulnerabilities as referenced in the TNS-2024-10 advisory.

  - Security Center leverages third-party software to help provide underlying functionality. Several of the
    third-party components (Apache, PHP) were found to contain vulnerabilities, and updated versions have been
    made available by the providers.Out of caution and in line with best practice, Tenable has opted to
    upgrade these components to address the potential impact of the issues. Security Center 6.4.0 updates
    Apache to version 2.4.59 and PHP to version 8.2.13 to address the identified vulnerabilities.Additionally,
    two separate vulnerabilities were discovered, reported and fixed:A stored cross site scripting
    vulnerability exists in Tenable Security Center where an authenticated, remote attacker could inject HTML
    code into a web application scan result page. - CVE-2024-1891An improper privilege management
    vulnerability exists in Tenable Security Center where an authenticated, remote attacker could view
    unauthorized objects and launch scans without having the required privileges. - CVE-2024-5759 Tenable has
    released Security Center 6.4.0 to address these issues. The installation files can be obtained from the
    Tenable Downloads Portal: https://www.tenable.com/downloads/security-center (CVE-2023-38709,
    CVE-2024-1874, CVE-2024-1891, CVE-2024-24795, CVE-2024-27316, CVE-2024-3096, CVE-2024-5759)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/downloads/security-center");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/TNS-2024-10");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Tenable Security Center 6.4.0 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-27316");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-5759");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vendor_severity", value:"Critical");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/06/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/10");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:security_center");
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
  { 'max_version' : '6.3.0', 'fixed_display' : 'Upgrade to 6.4.0 or later' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE,
    flags:{'xss':TRUE}
);
