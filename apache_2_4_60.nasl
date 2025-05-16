#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(201198);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/02");

  script_cve_id(
    "CVE-2024-36387",
    "CVE-2024-38472",
    "CVE-2024-38473",
    "CVE-2024-38474",
    "CVE-2024-38475",
    "CVE-2024-38476",
    "CVE-2024-38477",
    "CVE-2024-39573"
  );
  script_xref(name:"IAVA", value:"2024-A-0378-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2025/05/22");

  script_name(english:"Apache 2.4.x < 2.4.60 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apache httpd installed on the remote host is prior to 2.4.60. It is, therefore, affected by multiple
vulnerabilities as referenced in the 2.4.60 advisory.

  - Serving WebSocket protocol upgrades over a HTTP/2 connection could result in a Null Pointer dereference,
    leading to a crash of the server process, degrading performance. (CVE-2024-36387)

  - SSRF in Apache HTTP Server on Windows allows to potentially leak NTML hashes to a malicious server via
    SSRF and malicious requests or content Users are recommended to upgrade to version 2.4.60 which fixes this
    issue. Note: Existing configurations that access UNC paths will have to configure new directive UNCList
    to allow access during request processing. (CVE-2024-38472)

  - Encoding problem in mod_proxy in Apache HTTP Server 2.4.59 and earlier allows request URLs with incorrect
    encoding to be sent to backend services, potentially bypassing authentication via crafted requests. Users
    are recommended to upgrade to version 2.4.60, which fixes this issue. (CVE-2024-38473)

  - Substitution encoding issue in mod_rewrite in Apache HTTP Server 2.4.59 and earlier allows attacker to
    execute scripts in directories permitted by the configuration but not directly reachable by any URL or
    source disclosure of scripts meant to only to be executed as CGI. Users are recommended to upgrade to
    version 2.4.60, which fixes this issue. Some RewriteRules that capture and substitute unsafely will now
    fail unless rewrite flag UnsafeAllow3F is specified. (CVE-2024-38474)

  - Improper escaping of output in mod_rewrite in Apache HTTP Server 2.4.59 and earlier allows an attacker to
    map URLs to filesystem locations that are permitted to be served by the server but are not
    intentionally/directly reachable by any URL, resulting in code execution or source code disclosure.
    Substitutions in server context that use a backreferences or variables as the first segment of the
    substitution are affected. Some unsafe RewiteRules will be broken by this change and the rewrite flag
    UnsafePrefixStat can be used to opt back in once ensuring the substitution is appropriately constrained.
    (CVE-2024-38475)

  - Vulnerability in core of Apache HTTP Server 2.4.59 and earlier are vulnerably to information disclosure,
    SSRF or local script execution via backend applications whose response headers are malicious or
    exploitable. Users are recommended to upgrade to version 2.4.60, which fixes this issue. (CVE-2024-38476)

  - null pointer dereference in mod_proxy in Apache HTTP Server 2.4.59 and earlier allows an attacker to crash
    the server via a malicious request. Users are recommended to upgrade to version 2.4.60, which fixes this
    issue. (CVE-2024-38477)

  - Potential SSRF in mod_rewrite in Apache HTTP Server 2.4.59 and earlier allows an attacker to cause unsafe
    RewriteRules to unexpectedly setup URL's to be handled by mod_proxy. Users are recommended to upgrade to
    version 2.4.60, which fixes this issue. (CVE-2024-39573)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache version 2.4.60 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-38476");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/01");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:httpd");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:http_server");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("apache_http_version.nasl", "apache_http_server_nix_installed.nbin", "apache_httpd_win_installed.nbin");
  script_require_keys("installed_sw/Apache");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

app_info = vcf::apache_http_server::combined_get_app_info(app:'Apache');

var constraints = [
  { 'min_version' : '2.4.0', 'max_version' : '2.4.59', 'fixed_version' : '2.4.60' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
