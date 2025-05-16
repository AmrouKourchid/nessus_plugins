#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(235081);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/02");

  script_cve_id("CVE-2025-31160");
  script_xref(name:"IAVA", value:"2025-A-0210");

  script_name(english:"Atop 2.4.x < 2.11.1 DoS (CVE-2025-31160)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a program that is affected by denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"atop through 2.11.0 allows local users to cause a denial of service (e.g., assertion failure and application exit) or 
possibly have unspecified other impact by running certain types of unprivileged processes while a different user runs 
atop.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.atoptool.nl/downloadatop.php");
  script_set_attribute(attribute:"solution", value:
"Upgrade Atop to version 2.11.1 or later");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-31160");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/02/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/02/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/05/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atop_project:atop");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("atop_nix_installed.nbin");
  script_require_keys("installed_sw/Atop");

  exit(0);
}

include('vdf.inc');

var vuln_data = {
  'metadata': {'spec_version': '1.0'},
  'requires': [{'scope': 'target', 'match': {'os': 'linux'}}],
  'checks': [
    {
      'product':{'name': 'Atop', 'type': 'app'},
      'check_algorithm': 'default',
      'constraints': [
        {
          'min_version':'2.4.0', 'fixed_version': '2.11.1'
        }
      ]
    }
  ]
};

var result = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_NOTE);
vdf::handle_check_and_report_errors(vdf_result:result);
