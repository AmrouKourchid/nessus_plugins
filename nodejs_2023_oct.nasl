#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(183390);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/23");

  script_cve_id(
    "CVE-2023-38552",
    "CVE-2023-39331",
    "CVE-2023-39332",
    "CVE-2023-39333",
    "CVE-2023-44487",
    "CVE-2023-45143"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/10/31");
  script_xref(name:"CEA-ID", value:"CEA-2024-0004");
  script_xref(name:"IAVB", value:"2023-B-0083-S");

  script_name(english:"Node.js 18.x < 18.18.2 / 20.x < 20.8.1 Multiple Vulnerabilities (Friday October 13 2023 Security Releases).");

  script_set_attribute(attribute:"synopsis", value:
"Node.js - JavaScript run-time environment is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Node.js installed on the remote host is prior to 18.18.2, 20.8.1. It is, therefore, affected by multiple
vulnerabilities as referenced in the Friday October 13 2023 Security Releases advisory.

  - Undici did not always clear Cookie headers on cross-origin redirects. By design, cookie headers are
    forbidden request headers, disallowing them to be set in RequestInit.headers in browser environments.
    Since undici handles headers more liberally than the spec, there was a disconnect from the assumptions the
    spec made, and undici's implementation of fetch. As such this may lead to accidental leakage of cookie to
    a 3rd-party site or a malicious attacker who can control the redirection target (ie. an open redirector)
    to leak the cookie to the 3rd party site. More details area available in GHSA-wqq4-5wpv-mx2g
    (CVE-2023-45143)

  - Rapidly creating and cancelling streams (HEADERS frame immediately followed by RST_STREAM) without bound
    causes denial of service. See https://www.cve.org/CVERecord?id=CVE-2023-44487 for details. Impacts:
    (CVE-2023-44487)

  - A previously disclosed vulnerability (CVE-2023-30584) was patched insufficiently. The new path traversal
    vulnerability arises because the implementation does not protect itself against the application
    overwriting built-in utility functions with user-defined implementations. Impacts: Please note that at the
    time this CVE is issued, the permission model is an experimental feature of Node.js. Thanks to Tobias
    Nieen who reported and created the security patch. (CVE-2023-39331)

  - Various node:fs functions allow specifying paths as either strings or Uint8Array objects. In Node.js
    environments, the Buffer class extends the Uint8Array class. Node.js prevents path traversal through
    strings (see CVE-2023-30584) and Buffer objects (see CVE-2023-32004), but not through non-Buffer
    Uint8Array objects. This is distinct from CVE-2023-32004 (report 2038134), which only referred to Buffer
    objects. However, the vulnerability follows the same pattern using Uint8Array instead of Buffer. Impacts:
    Please note that at the time this CVE is issued, the permission model is an experimental feature of
    Node.js. Thanks to Tobias Nieen who reported and created the security patch. (CVE-2023-39332)

  - When the Node.js policy feature checks the integrity of a resource against a trusted manifest, the
    application can intercept the operation and return a forged checksum to node's policy implementation, thus
    effectively disabling the integrity check. Impacts: Please note that at the time this CVE is issued, the
    policy mechanism is an experimental feature of Node.js. Thanks to Tobias Nieen who reported and created
    the security patch. (CVE-2023-38552)

  - Maliciously crafted export names in an imported WebAssembly module can inject JavaScript code. The
    injected code may be able to access data and functions that the WebAssembly module itself does not have
    access to, similar to as if the WebAssembly module was a JavaScript module. Impacts: Thanks to dittyroma
    for reporting the issue and to Tobias Nieen for fixing it. (CVE-2023-39333)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://nodejs.org/en/blog/vulnerability/october-2023-security-releases/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?158127f8");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Node.js version 18.18.2 / 20.8.1 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-39332");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nodejs:node.js");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  { 'min_version' : '18.0.0', 'fixed_version' : '18.18.2' },
  { 'min_version' : '20.0.0', 'fixed_version' : '20.8.1' }
];
vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
