#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(234572);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/17");

  script_cve_id("CVE-2025-24986");

  script_name(english:"Microsoft Azure Promptflow Python Library promptflow-core < 1.17.2 RCE");

  script_set_attribute(attribute:"synopsis", value:
"A Python library installed on the remote host is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The detected version of Microsoft Azure Promptflow python package, promptflow-core, is prior to version 1.17.2. It is,
therefore, affected by a remote code execution vulnerability. An unauthenticated, remote attacker can exploit this to
bypass authentication and execute unauthorized arbitrary commands.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-24986");
  # https://microsoft.github.io/promptflow/reference/changelog/promptflow-core.html#v1-17-2-2025-1-23
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6284fac1");
  script_set_attribute(attribute:"solution", value:
"Upgrade to promptflow-core version 1.17.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-24986");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/03/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/01/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:azure_promptflow");
  script_set_attribute(attribute:"asset_categories", value:"component");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("python_packages_win_installed.nbin","python_packages_installed_nix.nbin");
  script_require_keys("Python/Packages/Enumerated");

  exit(0);
}

include('python.inc');

var pkg = 'promptflow-core';

var lib_info = python::get_package_info(pkg_name:pkg);

var constraints = [
  { 'fixed_version' : '1.17.2' }
];

vcf::check_version_and_report(app_info:lib_info, constraints:constraints, severity:SECURITY_HOLE);
