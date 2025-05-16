#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(192945);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/19");

  script_cve_id("CVE-2024-27982", "CVE-2024-27983");
  script_xref(name:"IAVB", value:"2024-B-0033-S");

  script_name(english:"Node.js 18.x < 18.20.1 / 20.x < 20.12.1 / 21.x < 21.7.2 Multiple Vulnerabilities (Wednesday, April 3, 2024 Security Releases).");

  script_set_attribute(attribute:"synopsis", value:
"Node.js - JavaScript run-time environment is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Node.js installed on the remote host is prior to 18.20.1, 20.12.1, 21.7.2. It is, therefore, affected by
multiple vulnerabilities as referenced in the Wednesday, April 3, 2024 Security Releases advisory.

  - An attacker can make the Node.js HTTP/2 server completely unavailable by sending a small amount of HTTP/2
    frames packets with a few HTTP/2 frames inside. It is possible to leave some data in nghttp2 memory after
    reset when headers with HTTP/2 CONTINUATION frame are sent to the server and then a TCP connection is
    abruptly closed by the client triggering the Http2Session destructor while header frames are still being
    processed (and stored in memory) causing a race condition. Impacts: Thank you, to bart for reporting this
    vulnerability and Anna Henningsen for fixing it. (CVE-2024-27983)

  - The team has identified a vulnerability in the http server of the most recent version of Node, where
    malformed headers can lead to HTTP request smuggling. Specifically, if a space is placed before a content-
    length header, it is not interpreted correctly, enabling attackers to smuggle in a second request within
    the body of the first. Impacts: Thank you, to bpingel for reporting this vulnerability and Paolo Insogna
    for fixing it.  Summary The Node.js project will release new versions of the 18.x, 20.x, 21.x releases
    lines on or shortly after, Wednesday, April 3, 2024 in order to address: (CVE-2024-27982)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://nodejs.org/en/blog/vulnerability/april-2024-security-releases/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Node.js version 18.20.1 / 20.12.1 / 21.7.2 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-27983");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nodejs:node.js");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  { 'min_version' : '18.0.0', 'fixed_version' : '18.20.1' },
  { 'min_version' : '20.0.0', 'fixed_version' : '20.12.1' },
  { 'min_version' : '21.0.0', 'fixed_version' : '21.7.2' }
];
vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
