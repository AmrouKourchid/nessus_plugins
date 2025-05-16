#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(214447);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/21");

  script_cve_id("CVE-2025-21502");

  script_name(english:"Azul Zulu Java Vulnerability (2025-01-21)");

  script_set_attribute(attribute:"synopsis", value:
"Azul Zulu OpenJDK is affected a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Azul Zulu installed on the remote host is 11 prior to 11.77.14 / 17 prior to 17.55.14 / 21 prior to
21.39.14 / 23 prior to 23.32.12. It is, therefore, affected by a vulnerability as referenced in the 2025-01-21 advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://docs.azul.com/core/release/january-2025/release-notes");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2025 Azul Zulu OpenJDK Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-21502");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/01/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/01/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/01/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:azul:zulu");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("zulu_java_nix_installed.nbin", "zulu_java_win_installed.nbin");
  script_require_keys("installed_sw/Java");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_list = ['Azul Zulu Java'];
var app_info = vcf::java::get_app_info(app:app_list);
var package_type = app_info['Reported Code'];

var constraints;

if ('SA' == package_type)
{
constraints = [
    { 'min_version' : '11.0.0', 'fixed_version' : '11.77.14', 'fixed_display' : 'Upgrade to a version 11.77.14 (SA) and above' },
    { 'min_version' : '17.0.0', 'fixed_version' : '17.55.14', 'fixed_display' : 'Upgrade to a version 17.55.14 (SA) and above' },
    { 'min_version' : '21.0.0', 'fixed_version' : '21.39.14', 'fixed_display' : 'Upgrade to a version 21.39.14 (SA) and above' },
    { 'min_version' : '23.0.0', 'fixed_version' : '23.32.12', 'fixed_display' : 'Upgrade to a version 23.32.12 (SA) and above' }
  ];
}
else if ('CA' == package_type)
{
  constraints = [
    { 'min_version' : '11.0.0', 'fixed_version' : '11.78.15', 'fixed_display' : 'Upgrade to a version 11.78.15 (CA) and above' },
    { 'min_version' : '17.0.0', 'fixed_version' : '17.56.15', 'fixed_display' : 'Upgrade to a version 17.56.15 (CA) and above' },
    { 'min_version' : '21.0.0', 'fixed_version' : '21.40.17', 'fixed_display' : 'Upgrade to a version 21.40.17 (CA) and above' },
    { 'min_version' : '23.0.0', 'fixed_version' : '23.32.11', 'fixed_display' : 'Upgrade to a version 23.32.11 (CA) and above' }
  ];
}

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
