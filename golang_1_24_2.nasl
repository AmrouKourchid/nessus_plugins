#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(233871);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/08");

  script_cve_id("CVE-2025-22871");
  script_xref(name:"IAVB", value:"2025-B-0048-S");

  script_name(english:"Golang 1.24 < 1.24.2");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by a request smuggling vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Golang running on the remote host is 1.24 prior to 1.24.2. It is, therefore, is affected by
multiple vulnerabilities:

  - Unlike request headers, where we are allowed to leniently accept a bare LF in place of a CRLF, 
    chunked bodies must always use CRLF line terminators. We were already enforcing this for chunk-data lines;
    do so for chunk-size lines as well. Also reject bare CRs anywhere other than as part of the CRLF terminator.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://go-review.googlesource.com/c/go/+/657056");
  script_set_attribute(attribute:"see_also", value:"https://github.com/golang/go/issues/72011");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Golang Go version 1.24.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-22871");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/02/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/03/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:golang:go");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("golang_win_installed.nbin", "golang_macos_installed.nbin");
  script_require_keys("installed_sw/Golang Go Programming Language");

  exit(0);
}

include('vdf.inc');

var vuln_data = {
  'metadata': {'spec_version': '1.0'},
  'requires': [{'scope': 'target'}],
   'checks': [{
      'product':{'name': 'Golang Go Programming Language', 'type': 'app'},
      'check_algorithm': 'default',
      'constraints': [
        {
          'fixed_version': '1.24.2'
        }
      ]
    }
  ]
};

var result = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_WARNING);
vdf::handle_check_and_report_errors(vdf_result:result);