#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(183391);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/29");

  script_cve_id("CVE-2023-43622", "CVE-2023-45802");
  script_xref(name:"IAVA", value:"2023-A-0572-S");

  script_name(english:"Apache 2.4.x < 2.4.58 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apache httpd installed on the remote host is prior to 2.4.58. It is, therefore, affected by multiple
vulnerabilities as referenced in the 2.4.58 advisory.

  - Apache HTTP Server: DoS in HTTP/2 with initial windows size 0: An attacker, opening a HTTP/2 connection
    with an initial window size of 0, was able to block handling of that connection indefinitely in Apache
    HTTP Server. This could be used to exhaust worker resources in the server, similar to the well known slow
    loris attack pattern. This has been fixed in version 2.4.58, so that such connection are terminated
    properly after the configured connection timeout. This issue affects Apache HTTP Server: from 2.4.55
    through 2.4.57. Users are recommended to upgrade to version 2.4.58, which fixes the issue.
    Acknowledgements: (CVE-2023-43622)

  - Apache HTTP Server: HTTP/2 stream memory not reclaimed right away on RST: When a HTTP/2 stream was reset
    (RST frame) by a client, there was a time window were the request's memory resources were not reclaimed
    immediately. Instead, de-allocation was deferred to connection close. A client could send new requests and
    resets, keeping the connection busy and open and causing the memory footprint to keep on growing. On
    connection close, all resources were reclaimed, but the process might run out of memory before that. This
    was found by the reporter during testing of CVE-2023-44487 (HTTP/2 Rapid Reset Exploit) with their own
    test client. During normal HTTP/2 use, the probability to hit this bug is very low. The kept memory
    would not become noticeable before the connection closes or times out. Users are recommended to upgrade to
    version 2.4.58, which fixes the issue. Acknowledgements: (CVE-2023-45802)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache version 2.4.58 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-43622");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/09/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/19");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:httpd");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:http_server");
  script_set_attribute(attribute:"generated_plugin", value:"former");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("apache_http_version.nasl", "apache_http_server_nix_installed.nbin", "apache_httpd_win_installed.nbin");
  script_require_keys("installed_sw/Apache");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::apache_http_server::combined_get_app_info(app:'Apache');

var constraints = [
  { 'max_version' : '2.4.57', 'fixed_version' : '2.4.58' , 'modules':['mod_http2', 'mod_macro']}
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
