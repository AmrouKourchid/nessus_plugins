#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(213281);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/17");

  script_cve_id("CVE-2024-10973");
  script_xref(name:"IAVB", value:"2024-B-0197-S");

  script_name(english:"Keycloak 25.0.x < 26.0.6 Information Disclosure (GHSA-6mpx-pmgp-ww49)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"Keycloak versions installed prior to 26.0.6 are affected by an information disclosure vulnerability as 
referenced in the advisory.

  - A vulnerability was found in Keycloak. The environment option `KC_CACHE_EMBEDDED_MTLS_ENABLED` does not 
    work and the JGroups replication configuration is always used in plain text which can allow an attacker 
    that has access to adjacent networks related to JGroups to read sensitive information. (CVE-2024-10973)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/advisories/GHSA-6mpx-pmgp-ww49");
  script_set_attribute(attribute:"solution", value:
"Upgrade Keycloak to 26.0.6 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-10973");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/12/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/12/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:keycloak:keycloak");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("keycloak_nix_installed.nbin");
  script_require_keys("Host/local_checks_enabled", "Host/uname");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Keycloak');

var constraints = [ {'min_version': '25.0', 'fixed_version': '26.0.6'}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
