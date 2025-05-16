#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(216260);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/25");

  script_cve_id("CVE-2025-0518");
  script_xref(name:"IAVB", value:"2025-B-0018-S");

  script_name(english:"FFmpeg < 7.2 Out-of-bounds Read");

  script_set_attribute(attribute:"synopsis", value:
"The version of FFmpeg installed on the remote host is affected by a out-of-bounds read vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of FFmpeg installed on the remote host is 7.1 prior to 7.2. It is, therefore, affected by a vulnerability:

  - Unchecked Return Value, Out-of-bounds Read vulnerability in FFmpeg allows Read Sensitive Constants Within an 
    executable. (CVE-2025-0518)

Nessus has not tested for these issues but has instead relied only on the application's self-reported version number.");
  # https://github.com/FFmpeg/FFmpeg/commit/b5b6391d64807578ab872dc58fb8aa621dcfc38a
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?40ca01ee");
  script_set_attribute(attribute:"see_also", value:"https://ffmpeg.org/security.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ffmpeg version 7.2 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:A/VC:L/VI:N/VA:N/SC:L/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:U");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-0518");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/01/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/01/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ffmpeg:ffmpeg");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ffmpeg_nix_installed.nbin");
  script_require_keys("installed_sw/FFmpeg");

  exit(0);
}

include('vcf.inc');

var app = 'FFmpeg';

var app_info = vcf::get_app_info(app:app);
vcf::check_all_backporting(app_info:app_info);

# There is no fixed version yet but the fix has been added to 7.2-dev https://github.com/FFmpeg/FFmpeg/releases/tag/n7.2-dev
# This should become a formal release at some time in the future.
var constraints = [
  { 'min_version' : '7.1', 'fixed_version' : '7.2' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
