#%NASL_MIN_LEVEL 80900
##
# (C) Tenable Inc.
##

include('compat.inc');

if (description)
{
  script_id(210586);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/11");

  script_cve_id("CVE-2024-45802");
  script_xref(name:"IAVB", value:"2024-B-0168");

  script_name(english:"Squid 3.x < 6.10 / 7.0.0 DoS (SQUID-2024:04)");

  script_set_attribute(attribute:"synopsis", value:
"The remote proxy server is affected by a denial of service vulnerability");
  script_set_attribute(attribute:"description", value:
"Squid is an open source caching proxy for the Web supporting HTTP, HTTPS, FTP, and more. Due to Input Validation, 
Premature Release of Resource During Expected Lifetime, and Missing Release of Resource after Effective Lifetime bugs, 
Squid is vulnerable to Denial of Service attacks by a trusted server against all clients using the proxy. This bug is 
fixed in the default build configuration of Squid version 6.10.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  # https://github.com/squid-cache/squid/security/advisories/GHSA-f975-v7qw-q7hj
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c74a1110");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Squid version 6.10 or 7.0.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-45802");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/08");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:squid-cache:squid");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("squid_version.nasl");
  script_require_keys("installed_sw/Squid", "Settings/ParanoidReport");
  script_require_ports("Services/http_proxy", 3128, 8080);

  exit(0);
}

include('http.inc');
include('vcf.inc');

get_install_count(app_name:'Squid', exit_if_zero:TRUE);

if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

var port = get_http_port(default:3128);

var app_info = vcf::get_app_info(app:'Squid', port:port, webapp:TRUE);

var constraints = [
  {'min_version':'3.0', 'fixed_version':'6.10', 'fixed_display':'6.10 / 7.0'},
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
