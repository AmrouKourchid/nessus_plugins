#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(190347);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/28");

  script_cve_id("CVE-2024-24815", "CVE-2024-24816");
  script_xref(name:"IAVA", value:"2024-A-0077-S");

  script_name(english:"CKEditor 4.x < 4.24.0-lts Multitple XSS");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server may be affected by multiple cross site scripting vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of CKEditor included on the remote web host is 4.x prior to 4.24.0-lts. It may, therefore, be affected by
multiple cross-site scripting (XSS) vulnerabilities.

 - A cross-site scripting vulnerability affecting editor instances that enabled full-page editing mode or
   enabled CDATA elements in Advanced Content Filtering configuration (defaults to `script` and `style`
   elements). The vulnerability allows attackers to inject malformed HTML content bypassing Advanced
   Content Filtering mechanism, which could result in executing JavaScript code. An attacker could abuse
   faulty CDATA content detection and use it to prepare an intentional attack on the editor. (CVE-2024-24815)

 - A cross-site scripting vulnerability in samples that use the `preview` feature. All integrators that use
   these samples in the production code can be affected. The vulnerability allows an attacker to execute
   JavaScript code by abusing the misconfigured preview feature. (CVE-2024-24816)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://github.com/ckeditor/ckeditor4/security/advisories/GHSA-fq6h-4g8v-qqvm
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7723975d");
  # https://github.com/ckeditor/ckeditor4/security/advisories/GHSA-mw2c-vx6j-mg76
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?661569b4");
  script_set_attribute(attribute:"see_also", value:"https://ckeditor.com/cke4/release-notes");
  script_set_attribute(attribute:"solution", value:
"Upgrade to CKEditor 4.24.0-lts or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-24816");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cksource:ckeditor");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cksource_ckeditor_cdn_detect.nbin");
  script_require_keys("installed_sw/CKSource CKEditor");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::combined_get_app_info(app:'CKSource CKEditor');

if (app_info['Major Version'] != 4)
  vcf::audit(app_info);

var constraints = [
  {'min_version': '4.0', 'fixed_version':'4.24.0', 'fixed_display': '4.24.0-lts'}
];

# Making paranoid due config requirements
vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  require_paranoia:TRUE,
  flags:{xss:TRUE}
);

