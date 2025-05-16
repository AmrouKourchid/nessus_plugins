#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(196900);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/07");

  script_cve_id("CVE-2024-24787");
  script_xref(name:"IAVB", value:"2024-B-0052-S");

  script_name(english:"Golang < 1.21.10, 1.22.x < 1.22.3 Code Execution");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by a code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Golang running on the remote host is prior to 1.21.10 or 1.22.x prior to 1.22.3. It is, therefore, 
affected by a code execution vulnerability. On Darwin, building a Go module which contains CGO can trigger arbitrary
code execution when using the Apple version of ld, due to usage of the -lto_library flag in a '#cgo LDFLAGS' directive.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://pkg.go.dev/vuln/GO-2024-2825");
  script_set_attribute(attribute:"see_also", value:"https://groups.google.com/g/golang-announce/c/wkkO4P9stm0");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Golang Go version 1.21.10, 1.22.3, or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-24787");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:golang:go");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("golang_macos_installed.nbin");
  script_require_keys("installed_sw/Golang Go Programming Language");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Golang Go Programming Language');

var constraints = [
  { 'min_version' : '0.0', 'fixed_version' : '1.21.10' },
  { 'min_version' : '1.22.0', 'fixed_version' : '1.22.3' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);