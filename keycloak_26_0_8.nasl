#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(214216);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/21");

  script_cve_id("CVE-2024-11734", "CVE-2024-11736");
  script_xref(name:"IAVB", value:"2025-B-0006-S");

  script_name(english:"Keycloak 26.0.8 Multiple Vulnerabilities (26_0_8)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The version of Keycloak installed on the remote host is prior to 26.0.8. It is, therefore, affected by multiple
vulnerabilities as referenced in the 26_0_8 advisory.

  - A denial of service vulnerability was found in Keycloak that could allow an administrative user with the
    right to change realm settings to disrupt the service. This action is done by modifying any of the
    security headers and inserting newlines, which causes the Keycloak server to write to a request that has
    already been terminated, leading to the failure of said request. (CVE-2024-11734)

  - A vulnerability was found in Keycloak. Admin users may have to access sensitive server environment
    variables and system properties through user-configurable URLs. When configuring backchannel logout URLs
    or admin URLs, admin users can include placeholders like ${env.VARNAME} or ${PROPNAME}. The server
    replaces these placeholders with the actual values of environment variables or system properties during
    URL processing. (CVE-2024-11736)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/advisories/GHSA-w3g8-r9gw-qrh8");
  script_set_attribute(attribute:"see_also", value:"https://github.com/advisories/GHSA-f4v7-3mww-9gc2");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Keycloak version 26.0.8 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:M/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-11736");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/01/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/01/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/01/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:keycloak:keycloak");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("keycloak_nix_installed.nbin");
  script_require_keys("Host/local_checks_enabled", "Host/uname", "installed_sw/Keycloak");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Keycloak');

var constraints = [
  { 'fixed_version' : '26.0.8' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
