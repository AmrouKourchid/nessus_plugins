#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(190856);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/03");

  script_cve_id(
    "CVE-2023-46809",
    "CVE-2024-21890",
    "CVE-2024-21891",
    "CVE-2024-21892",
    "CVE-2024-21896",
    "CVE-2024-22017",
    "CVE-2024-22019"
  );
  script_xref(name:"IAVB", value:"2024-B-0016-S");

  script_name(english:"Node.js 18.x < 18.19.1 / 20.x < 20.11.1 / 21.x < 21.6.2 Multiple Vulnerabilities (Wednesday February 14 2024 Security Releases).");

  script_set_attribute(attribute:"synopsis", value:
"Node.js - JavaScript run-time environment is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Node.js installed on the remote host is prior to 18.19.1, 20.11.1, 21.6.2. It is, therefore, affected by
multiple vulnerabilities as referenced in the Wednesday February 14 2024 Security Releases advisory.

  - On Linux, Node.js ignores certain environment variables if those may have been set by an unprivileged user
    while the process is running with elevated privileges with the only exception of CAP_NET_BIND_SERVICE. Due
    to a bug in the implementation of this exception, Node.js incorrectly applies this exception even when
    certain other capabilities have been set. This allows unprivileged users to inject code that inherits the
    process's elevated privileges. Impacts: Thank you, to Tobias Nieen for reporting this vulnerability and
    for fixing it. (CVE-2024-21892)

  - A vulnerability in Node.js HTTP servers allows an attacker to send a specially crafted HTTP request with
    chunked encoding, leading to resource exhaustion and denial of service (DoS). The server reads an
    unbounded number of bytes from a single connection, exploiting the lack of limitations on chunk extension
    bytes. The issue can cause CPU and network bandwidth exhaustion, bypassing standard safeguards like
    timeouts and body size limits. Impacts: Thank you, to Bartek Nowotarski for reporting this vulnerability
    and thank you Paolo Insogna for fixing it. (CVE-2024-22019)

  - The permission model protects itself against path traversal attacks by calling path.resolve() on any paths
    given by the user. If the path is to be treated as a Buffer, the implementation uses Buffer.from() to
    obtain a Buffer from the result of path.resolve(). By monkey-patching Buffer internals, namely,
    Buffer.prototype.utf8Write, the application can modify the result of path.resolve(), which leads to a path
    traversal vulnerability. Impacts: Please note that at the time this CVE was issued, the permission model
    is an experimental feature of Node.js. Thank you, to Tobias Nieen for reporting this vulnerability and
    for fixing it. (CVE-2024-21896)

  - setuid() does not affect libuv's internal io_uring operations if initialized before the call to setuid().
    This allows the process to perform privileged operations despite presumably having dropped such privileges
    through a call to setuid(). Impacts: Thank you, to valette for reporting this vulnerability and thank you
    Tobias Nieen for fixing it. (CVE-2024-22017)

  - A vulnerability in the privateDecrypt() API of the crypto library, allowed a covert timing side-channel
    during PKCS#1 v1.5 padding error handling. The vulnerability revealed significant timing differences in
    decryption for valid and invalid ciphertexts. This poses a serious threat as attackers could remotely
    exploit the vulnerability to decrypt captured RSA ciphertexts or forge signatures, especially in scenarios
    involving API endpoints processing Json Web Encryption messages. Impacts: Thank you, to hkario for
    reporting this vulnerability and thank you Michael Dawson for fixing it. (CVE-2023-46809)

  - Node.js depends on multiple built-in utility functions to normalize paths provided to node:fs functions,
    which can be overwitten with user-defined implementations leading to filesystem permission model bypass
    through path traversal attack. Impacts: Please note that at the time this CVE was issued, the permission
    model is an experimental feature of Node.js. Thank you, to xion for reporting this vulnerability and thank
    you Rafael Gonzaga for fixing it. (CVE-2024-21891)

  - The Node.js Permission Model does not clarify in the documentation that wildcards should be only used as
    the last character of a file path. For example: --allow-fs-read=/home/node/.ssh/*.pub will ignore pub and
    give access to everything after .ssh/. Impacts: Please note that at the time this CVE was issued, the
    permission model is an experimental feature of Node.js. Thank you, to Tobias Nieen for reporting this
    vulnerability and thank you Rafael Gonzaga for fixing it. (CVE-2024-21890)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://nodejs.org/en/blog/vulnerability/february-2024-security-releases/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?313add11");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Node.js version 18.19.1 / 20.11.1 / 21.6.2 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-21896");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nodejs:node.js");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

var constraints = [
  { 'min_version' : '18', 'fixed_version' : '18.19.1' },
  { 'min_version' : '20', 'fixed_version' : '20.11.1' },
  { 'min_version' : '21', 'fixed_version' : '21.6.2' }
];
vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
