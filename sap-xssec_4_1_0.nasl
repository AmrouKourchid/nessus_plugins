#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(194476);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/23");

  script_cve_id("CVE-2023-50423");

  script_name(english:"SAP BTP Python Library sap-xssec < 4.1.0 Privilege Escalation");

  script_set_attribute(attribute:"synopsis", value:
"A Python library installed on the remote host is affected by a privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The detected version of SAP BTP python package, sap-xssec, is prior to version 4.1.0. It is, therefore, affected by a
privilege escalation vulnerability. An unauthenticated, remote attacker can exploit this to gain arbitrary permissions
within the applicaiton.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://me.sap.com/notes/3411067");
  script_set_attribute(attribute:"solution", value:
"Upgrade to sap-xssec version 4.1.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-50423");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/12/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sap:sap-xssec");
  script_set_attribute(attribute:"asset_categories", value:"component");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("python_packages_installed_nix.nbin");
  script_require_keys("Host/nix/Python/Packages/Enumerated");

  exit(0);
}

include('vcf.inc');
include('python.inc');

get_kb_item_or_exit("Host/nix/Python/Packages/Enumerated");
var os = 'nix';
var pkg = 'sap-xssec';
var found_lib, libs = [];

found_lib = python::query_python_package(os:os, pkg_name:pkg);

if (!empty_or_null(found_lib))
  foreach (var found in found_lib)
  {
    found.pkg_name = pkg;
    append_element(var:libs, value:found);
  }


if (empty_or_null(libs))
  audit(AUDIT_HOST_NOT, 'affected');

var lib = branch(libs);
var lib_info = {
  'app' : lib.pkg_name,
  'version' : lib.version,
  'display_version' : lib.version,
  'parsed_version' : vcf::parse_version(lib.version),
  'path' : lib.path
};

var constraints = [
  { 'fixed_version' : '4.1.0' }
];

vcf::check_version_and_report(app_info:lib_info, constraints:constraints, severity:SECURITY_HOLE);
