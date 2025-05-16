#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(214404);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/24");

  script_cve_id("CVE-2025-23083", "CVE-2025-23084", "CVE-2025-23085");
  script_xref(name:"IAVB", value:"2025-B-0012");

  script_name(english:"Node.js 18.x < 18.20.6 / 20.x < 20.18.2 / 22.x < 22.13.1 / 23.x < 23.6.1 Multiple Vulnerabilities (Tuesday, January 21, 2025 Security Releases).");

  script_set_attribute(attribute:"synopsis", value:
"Node.js - JavaScript run-time environment is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Node.js installed on the remote host is prior to 18.20.6, 20.18.2, 22.13.1, 23.6.1. It is, therefore,
affected by multiple vulnerabilities as referenced in the Tuesday, January 21, 2025 Security Releases advisory.

  - A memory leak could occur when a remote peer abruptly closes the socket without sending a GOAWAY
    notification. Additionally, if an invalid header was detected by nghttp2, causing the connection to be
    terminated by the peer, the same leak was triggered. This flaw could lead to increased memory consumption
    and potential denial of service under certain conditions. This vulnerability affects HTTP/2 Server users
    on Node.js v18.x, v20.x, v22.x and v23.x. Impact: Thank you, to newtmitch for reporting this vulnerability
    and thank you RafaelGSS for fixing it. (CVE-2025-23085)

  - With the aid of the diagnostics_channel utility, an event can be hooked into whenever a worker thread is
    created. This is not limited only to workers but also exposes internal workers, where an instance of them
    can be fetched, and its constructor can be grabbed and reinstated for malicious usage. This vulnerability
    affects Permission Model users (--permission) on Node.js v20, v22, and v23. Impact: Thank you, to
    leodog896 for reporting this vulnerability and thank you RafaelGSS for fixing it. (CVE-2025-23083)

  - A vulnerability has been identified in Node.js, specifically affecting the handling of drive names in the
    Windows environment. Certain Node.js functions do not treat drive names as special on Windows. As a
    result, although Node.js assumes a relative path, it actually refers to the root directory. On Windows, a
    path that does not start with the file separator is treated as relative to the current directory. This
    vulnerability affects Windows users of path.join API. Impact: Thank you, to taise for reporting this
    vulnerability and thank you tniessen for fixing it. (CVE-2025-23084)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://nodejs.org/en/blog/vulnerability/january-2025-security-releases/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?68bc9901");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Node.js version 18.20.6 / 20.18.2 / 22.13.1 / 23.6.1 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-23085");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2025-23083");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/01/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/01/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/01/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nodejs:node.js");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nodejs_win_installed.nbin", "nodejs_installed_nix.nbin", "macosx_nodejs_installed.nbin");
  script_require_keys("installed_sw/Node.js");

  exit(0);
}

include('vcf.inc');

var win_local = FALSE;
var os = get_kb_item_or_exit('Host/OS');
if ('windows' >< tolower(os)) win_local = TRUE;

var app_info = vcf::get_app_info(app:'Node.js', win_local:win_local);
vcf::check_granularity(app_info:app_info, sig_segments:3);
vcf::check_all_backporting(app_info:app_info);

var constraints = [
  { 'min_version' : '18.0.0', 'fixed_version' : '18.20.6' },
  { 'min_version' : '20.0.0', 'fixed_version' : '20.18.2' },
  { 'min_version' : '22.0.0', 'fixed_version' : '22.13.1' },
  { 'min_version' : '23.0.0', 'fixed_version' : '23.6.1' }
];
vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
