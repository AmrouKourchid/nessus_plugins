#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(185425);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/09");

  script_name(english:"Foxit PDF Editor for Mac <= 11.1.5.0913 / 12.x <= 12.1.1.55342 / 13.0.0.61829 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A PDF toolkit installed on the remote macOS host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"According to its version, the Foxit PDF Editor for Mac application (previously named Foxit PhantomPDF for Mac)
installed on the remote macOS host is affected by multiple Use-After-Free or Out-of-Bounds Read vulnerabilities that
could be exploited by attackers to execute remote code or disclose information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a27a3e57");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Foxit PDF Editor for Mac version 13.0.1 or later");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score based on in depth analysis of the vendor advisory by Tenable.");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/11/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/11/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:foxitsoftware:phantom");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:foxitsoftware:phantompdf");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_foxit_phantompdf_installed.nbin");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "installed_sw/Foxit PhantomPDF");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('Host/local_checks_enabled');

var os = get_kb_item('Host/MacOSX/Version');
if (empty_or_null(os)) audit(AUDIT_OS_NOT, 'Mac OS X');

var app_info = vcf::get_app_info(app:'Foxit PhantomPDF');

# Affected 13.0.0.61829, 12.1.1.55342 and all previous 12.x versions, 11.1.5.0913 and earlier
var constraints = [
  { 'max_version' : '11.1.5.0913', 'fixed_display' : '13.0.1' },
  { 'min_version' : '12.0', 'max_version' : '12.1.1.55342', 'fixed_display' : '13.0.1' },
  { 'equal' : '13.0.0.61829', 'fixed_version' : '13.0.1' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
