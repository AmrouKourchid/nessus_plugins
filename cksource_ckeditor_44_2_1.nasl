#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(216916);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/27");

  script_cve_id("CVE-2025-25299");
  script_xref(name:"IAVA", value: "2025-A-0131");

  script_name(english:"CKEditor 41.3.0 < 44.2.1 XSS");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server may be affected by a cross site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of CKEditor included on the remote web host is 41.3.0 prior to 44.2.1. It may, therefore, be affected by
a cross-site scripting (XSS) vulnerability. This vulnerability affects user markers, which represent users' positions 
within the document. It can lead to unauthorized JavaScript code execution, which might happen with a very specific 
editor and token endpoint configuration. This vulnerability affects only installations with Real-time collaborative 
editing enabled. The problem has been recognized and patched. The fix is available in version 44.2.1 (and above). Users 
are advised to upgrade. There are no known workarounds for this vulnerability.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://github.com/ckeditor/ckeditor5/security/advisories/GHSA-j3mm-wmfm-mwvh
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3c32e362");
  script_set_attribute(attribute:"see_also", value:"https://ckeditor.com/blog/ckeditor-44-2-1-release-highlights/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to CKEditor 44.2.1 or later.");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-25299");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/02/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/02/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cksource:ckeditor");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cksource_ckeditor_cdn_detect.nbin");
  script_require_keys("installed_sw/CKSource CKEditor");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::combined_get_app_info(app:'CKSource CKEditor');

# Only vulnerable if premium feture real time collaboration is enabled
if (chomp(app_info['Package']) != 'full-all' && report_paranoia < 2)
{
  audit(AUDIT_POTENTIAL_VULN, 'CKSource CKEditor', app_info.version);
}

var constraints = [
  {'min_version': '41.3', 'fixed_version':'44.2.1'}
];

# Making paranoid due config requirements
vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  flags:{xss:TRUE}
);

