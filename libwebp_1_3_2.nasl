#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(182136);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/10/05");

  script_cve_id("CVE-2023-4863");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/10/04");

  script_name(english:"WebM Project WebP Image Library (libwebp) < 1.3.2 Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The image processing library is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of WebM Project WebP Image Library (libwebp) installed on the remote host is prior to 1.3.2. It is,
therefore, affected by a vulnerability:

  - Heap buffer overflow in libwebp prior to libwebp 1.3.2
    allowed a remote attacker to perform an out of bounds memory
    write via a specially crafted image. (CVE-2023-4863)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/webmproject/libwebp/releases/tag/v1.3.2");
  # https://www.tenable.com/blog/cve-2023-41064-cve-2023-4863-cve-2023-5129-faq-imageio-webp-zero-days
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?710a4ec7");
  script_set_attribute(attribute:"solution", value:
"Upgrade to WebM Project WebP Image Library (libwebp) version 1.3.2 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-4863");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/09/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/09/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:webmproject:libwebp");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("webm_project_webp_image_library_win_installed.nbin", "webm_project_webp_image_library_nix_installed.nbin");
  script_require_keys("installed_sw/WebM Project WebP Image Library");

  exit(0);
}

include('vcf.inc');

var win_local = FALSE;
var os = get_kb_item_or_exit('Host/OS');
if ('windows' >< tolower(os)) win_local = TRUE;

var app_info = vcf::get_app_info(app:'WebM Project WebP Image Library', win_local:win_local);

vcf::check_all_backporting(app_info:app_info);

var constraints = [
  { 'fixed_version' : '1.3.2' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
