#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(235470);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/09");

  script_cve_id("CVE-2025-22873");
  script_xref(name:"IAVB", value:"2025-B-0069");

  script_name(english:"Golang 1.24.x < 1.24.3 Directory Traversal");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by a directory traversal vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Golang running on the remote host is 1.24.x prior to 1.24.3. It is, therefore, affected by a directory
traversal vulnerability that makes it possible to improperly access the parent directory of an os.Root.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/golang/go/issues/73555");
  script_set_attribute(attribute:"see_also", value:"https://groups.google.com/g/golang-announce/c/UZoIkUT367A");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Golang Go version 1.24.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-22873");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/05/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/05/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:golang:go");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("golang_win_installed.nbin", "golang_macos_installed.nbin");
  script_require_keys("installed_sw/Golang Go Programming Language");

  exit(0);
}

include('vdf.inc');

# @tvdl-content
var vuln_data = {
  'metadata': {'spec_version': '1.0'},
  'checks': [
    {
      'product': {'name': 'Golang Go Programming Language', 'type': 'app'},
      'check_algorithm': 'default',
      'constraints': [
        {'min_version': '1.24.0', 'fixed_version': '1.24.3'}
      ]
    }
  ]
};

var result = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_WARNING);
vdf::handle_check_and_report_errors(vdf_result:result);
