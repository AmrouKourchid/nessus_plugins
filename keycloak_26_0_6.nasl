#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(212078);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/19");

  script_cve_id(
    "CVE-2024-9666",
    "CVE-2024-10039",
    "CVE-2024-10270",
    "CVE-2024-10451",
    "CVE-2024-10492"
  );
  script_xref(name:"IAVB", value:"2024-B-0184-S");

  script_name(english:"Keycloak < 24.0.9, 25.0.x < 26.0.6 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"Keycloak versions installed prior to 24.0.9, 25.0 prior to 26.0.6 are affected by multiple vulnerabilities as 
referenced in the advisory.

  - Deployments of Keycloak with a reverse proxy not using pass-through termination of TLS, with mTLS 
    enabled, are affected. This issue may allow an attacker on the local network to authenticate as any user  
    or client that leverages mTLS as the authentication mechanism. (CVE-2024-10039)

  - If untrusted data is passed to the SearchQueryUtils method, it could lead to a denial of service (DoS) 
    scenario by exhausting system resources due to a Regex complexity. (CVE-2024-10270)

  - A user with high privileges could read sensitive information from a Vault file that is not within the 
    expected context. This attacker must have previous high access to the Keycloak server in order to perform 
    resource creation, for example, an LDAP provider configuration and set up a Vault read file, which will 
    only inform whether that file exists or not. (CVE-2024-10492)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/advisories/GHSA-jgwc-jh89-rpgq");
  script_set_attribute(attribute:"see_also", value:"https://github.com/advisories/GHSA-93ww-43rr-79v3");
  script_set_attribute(attribute:"see_also", value:"https://github.com/advisories/GHSA-wq8x-cg39-8mrr");
  script_set_attribute(attribute:"see_also", value:"https://github.com/advisories/GHSA-5545-r4hg-rj4m");
  script_set_attribute(attribute:"see_also", value:"https://github.com/advisories/GHSA-v7gv-xpgf-6395");
  script_set_attribute(attribute:"solution", value:
"Upgrade Keycloak to 24.0.9, 26.0.6  or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:P");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-10270");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/11/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/11/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:keycloak:keycloak");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("keycloak_nix_installed.nbin");
  script_require_keys("Host/local_checks_enabled", "Host/uname");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Keycloak');

var constraints = [
  {'fixed_version': '24.0.9', 'fixed_display': 'See vendor advisory'},
  {'min_version': '25.0', 'fixed_version': '26.0.6'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
