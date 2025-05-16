#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(212711);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/16");

  script_cve_id("CVE-2024-8980");

  script_name(english:"Liferay Portal 7.0.0 < 7.4.3.102 XSS");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Script Console in Liferay Portal 7.0.0 through 7.4.3.101, and Liferay DXP 2023.Q3.1 through 2023.Q3.4, 7.4 GA 
through update 92, 7.3 GA through update 35, 7.2 GA through fix pack 20, 7.1 GA through fix pack 28, 7.0 GA through fix 
pack 102 and 6.2 GA through fix pack 173 does not sufficiently protect against Cross-Site Request Forgery (CSRF) 
attacks, which allows remote attackers to execute arbitrary Groovy script via a crafted URL or a XSS vulnerability.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://liferay.dev/portal/security/known-vulnerabilities");
  script_set_attribute(attribute:"solution", value:
"Upgrade Liferay Portal based upon the guidance specified in the advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-8980");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/09/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:liferay:liferay_portal");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("liferay_detect.nasl");
  script_require_keys("installed_sw/liferay_portal");
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::combined_get_app_info(app:'liferay_portal');

var constraints = [
  { 'min_version':'7.0.0', 'max_version':'7.0.6', 'fixed_version':'7.4.3.102' },
  { 'min_version':'7.1.0', 'max_version':'7.1.3', 'fixed_version':'7.4.3.102' },
  { 'min_version':'7.2.0', 'max_version':'7.2.1', 'fixed_version':'7.4.3.102' },
  { 'min_version':'7.3.0', 'max_version':'7.3.7', 'fixed_version':'7.4.3.102' },
  { 'min_version':'7.4.0', 'fixed_version':'7.4.3.102' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING,
    flags:{'xss':TRUE}
);
