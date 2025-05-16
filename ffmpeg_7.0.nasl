#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(193598);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/17");

  script_cve_id("CVE-2024-28661", "CVE-2023-49528");
  script_xref(name:"IAVB", value:"2024-B-0041-S");
  script_xref(name:"IAVB", value:"2024-B-0110-S");

  script_name(english:"FFmpeg < 7.0 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The version of FFmpeg installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of FFmpeg installed on the remote host is prior to 7.0. It is, therefore, affected by multiple
vulnerabilities:

  - Buffer Overflow vulnerability in FFmpeg version n6.1-3-g466799d4f5, allows a local attacker to execute
    arbitrary code and cause a denial of service (DoS) via the af_dialoguenhance.c:261:5 in the de_stereo
    component. (CVE-2023-49528)

  - An unspecified vulnerability exists in FFmpeg below version 7.0. (CVE-2024-28661)

Nessus has not tested for these issues but has instead relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://trac.ffmpeg.org/ticket/10691");
  script_set_attribute(attribute:"see_also", value:"https://ffmpeg.org/security.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ffmpeg version 7.0 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-28661");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-49528");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ffmpeg:ffmpeg");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ffmpeg_nix_installed.nbin");
  script_require_keys("installed_sw/FFmpeg");

  exit(0);
}

include('vcf.inc');

var app = 'FFmpeg';

var app_info = vcf::get_app_info(app:app);
vcf::check_all_backporting(app_info:app_info);

var constraints = [
  { 'fixed_version' : '7.0.0'}
];

# This plugin requires paranoia due to a severe lack of vulnerability information at the time of plugin release
vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    require_paranoia:TRUE,
    severity:SECURITY_WARNING
);
