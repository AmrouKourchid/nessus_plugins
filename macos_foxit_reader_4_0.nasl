#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(139329);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/10/09");

  script_cve_id("CVE-2020-9592", "CVE-2020-9596");

  script_name(english:"Foxit Reader < 4.0 Privilege Escalation (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"A PDF viewer installed on the remote macOS host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Foxit Reader for Mac installed on the remote macOS host is prior to 4.0. It is, therefore, affected by
a Signature Validation Bypass vulnerability that delivers incorrect validation results when validating certain PDF
files that have been modified maliciously or contains non-standard signatures.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.foxitsoftware.com/support/security-bulletins.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a27a3e57");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Foxit Reader for Mac version 4.0 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-9592");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:foxitsoftware:foxit_reader");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_foxit_reader_installed.nbin");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "installed_sw/Foxit Reader");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('Host/local_checks_enabled');

var os = get_kb_item('Host/MacOSX/Version');
if (empty_or_null(os)) audit(AUDIT_OS_NOT, 'Mac OS X');

var app_info = vcf::get_app_info(app:'Foxit Reader');

var constraints = [
  { 'max_version' : '3.4.0.1012', 'fixed_version' : '4.0' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
