#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(204790);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/12");

  script_cve_id("CVE-2024-39689");
  script_xref(name:"IAVA", value:"2024-A-0447");

  script_name(english:"Python Library Certifi < 2024.07.04 Untrusted Root Certificate");

  script_set_attribute(attribute:"synopsis", value:
"A Python library installed on the remote host is affected by a root certificate vulnerability.");
  script_set_attribute(attribute:"description", value:
"The detected version of Certifi python package, certifi, is prior to version 2024.07.04. Therefore, it contains
untrusted root certificates from GLOBALTRUST. An unauthenticated, remote attacker can exploit this to gain arbitrary permissions
within the application.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/advisories/GHSA-248v-346w-9cwc");
  script_set_attribute(attribute:"solution", value:
"Upgrade to certifi version 2024.07.04 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-39689");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:certifi");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"asset_categories", value:"component");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("unix_enum_sw.nasl", "python_packages_installed_nix.nbin");
  script_require_keys("Host/nix/packages", "Host/nix/Python/Packages/Enumerated");

  exit(0);
}

include('vcf.inc');
include('python.inc');
include('local_detection_nix.inc');

get_kb_item_or_exit("Host/nix/Python/Packages/Enumerated");
get_kb_item_or_exit("Host/nix/packages");

var os = 'nix';
var pkg = 'certifi';

var os_pkg = ldnix::search_packages([new('ldnix::pkg_target', 'python3-certifi', '(python[0-9]*-certifi)')]);
# if the package is found, the host has a version of certifi backported by the OS vendor
if (!empty_or_null(os_pkg) && report_paranoia < 2)
  audit(AUDIT_MANAGED_INSTALL, pkg + ' Python package');

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
  { 'min_version' : '2021.05.30' , 'fixed_version' : '2024.07.04' }
];

vcf::check_version_and_report(app_info:lib_info, constraints:constraints, severity:SECURITY_HOLE);
