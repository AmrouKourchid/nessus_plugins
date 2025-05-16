#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(192737);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/23");

  script_cve_id("CVE-2024-3094");
  script_xref(name:"IAVA", value:"2024-A-0327");

  script_name(english:"XZ Utils 5.6.0 / 5.6.1 Liblzma Backdoor Check");

  script_set_attribute(attribute:"synopsis", value:
"The version of XZ Utils installed on the remote host is affected by a backdoor vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of XZ Utils installed on the remote host is potentially affected by a backdoor vulnerability.

Note: This plugin is paranoid because not all instances of the affected versions of XZ Utils are 
known to be vulnerable to the backdoor. The method of installation of XZ Utils plays a role in whether 
the install is vulnerable or not. However, multiple vendors have rolled out remediation 
fixes as a precaution.

Nessus has not tested for this issue but has instead relied only on the application's 
self-reported version number.

As this detection can lead to potential false positives, it is recommended that manual 
verification of identified instances be performed.

For more information, refer to https://www.tenable.com/blog/frequently-asked-questions-cve-2024-3094-supply-chain-backdoor-in-xz-utils");
  # https://www.tenable.com/blog/frequently-asked-questions-cve-2024-3094-supply-chain-backdoor-in-xz-utils
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ff42ccd0");
  # https://www.cisa.gov/news-events/alerts/2024/03/29/reported-supply-chain-compromise-affecting-xz-utils-data-compression-library-cve-2024-3094
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?14f3969d");
  # https://community.tenable.com/s/article/How-does-Show-potential-false-alarms-impact-a-scan-scanning-in-paranoid-mode?language=en_US
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?179ce062");
  script_set_attribute(attribute:"solution", value:
"See vendor advisory.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-3094");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/03/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/01");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:xz-utils");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("xz_utils_nix_installed.nbin");
  script_require_keys("installed_sw/XZ Utils", "Settings/ParanoidReport");

  exit(0);
}

include('vcf.inc');

var app = 'XZ Utils';

if (report_paranoia < 2) audit(AUDIT_PARANOID);

var app_info = vcf::get_app_info(app:app);

var constraints = [
  { 'min_version' : '5.6.0', 'max_version' : '5.6.1', 'fixed_display' : 'See vendor advisory.'}
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
