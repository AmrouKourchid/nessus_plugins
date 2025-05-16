#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(216477);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/21");

  script_cve_id("CVE-2025-1391");
  script_xref(name:"IAVB", value:"2025-B-0027");

  script_name(english:"Keycloak 26.x < 26.0.10 / 26.1.x < 26.1.3 / 26.2.0 Improper Authorization");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The version of Keycloak installed on the remote host is 26.0 prior to 26.0.10, 26.1 prior to 26.1.3, or prior to 26.2.0. It is, 
therefore, affected by an Improper Authorization vulnerability. A flaw was found in the Keycloak organization feature, 
which allows the incorrect assignment of an organization to a user if their username or email matches the organization’s domain pattern. 
This issue occurs at the mapper level, leading to misrepresentation in tokens. If an application relies on 
these claims for authorization, it may incorrectly assume a user belongs to an organization they are not a 
member of, potentially granting unauthorized access or privileges.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/keycloak/keycloak/issues/37169");
  script_set_attribute(attribute:"see_also", value:"https://github.com/keycloak/keycloak/pull/37235/files");
  script_set_attribute(attribute:"see_also", value:"https://github.com/advisories/GHSA-rq4w-cjrr-h8w8");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2346082");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Keycloak version to 26.0.10, 26.1.3, 26.2.0 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-1391");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(284);

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/02/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/02/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:keycloak:keycloak");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
  { 'min_version' : '26.0', 'fixed_version' : '26.0.10' },
  { 'min_version' : '26.1.0', 'fixed_version' : '26.1.3', 'fixed_display' : '26.1.3, 26.2.0, or later'},

];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
