#%NASL_MIN_LEVEL 80900
#
# (C) Tenable Inc.
#

include('compat.inc');

if (description)
{
  script_id(233866);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/05");

  script_cve_id("CVE-2024-41713", "CVE-2024-55550");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2025/01/28");

  script_name(english:"Mitel MiCollab <= 9.8 SP2 (9.8.2.12) Multiple Vulnerabilities (MISA-2024-0029)");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the instance of Mitel MiCollab running on the remote web server is prior to
9.8 SP2 (9.8.2.12) and is, therefore, affected by multiple vulnerabilities:

  - A vulnerability in the NuPoint Unified Messaging (NPM) component of Mitel MiCollab through 9.8 SP1 FP2 (9.8.1.201)
    could allow an unauthenticated attacker to conduct a path traversal attack, due to insufficient input validation.
    (CVE-2024-41713)

  - Mitel MiCollab through 9.8 SP2 could allow an authenticated attacker with administrative privilege to conduct a
    local file read, due to insufficient input sanitization. (CVE-2024-55550)

Note that Nessus has not tested for these issues but has instead relied only on the 
application's self-reported version number.");
  # https://www.mitel.com/support/security-advisories/mitel-product-security-advisory-misa-2024-0029
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?26ea8c93");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mitel MiCollab version 9.8 SP2 (9.8.2.12) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-41713");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mitel:micollab");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mitel_micollab_detect.nbin");
  script_require_keys("installed_sw/Mitel MiCollab");
  script_require_ports("Services/www", 443);

  exit(0);
}

include('vcf.inc');
include('http.inc');

var port = get_http_port(default:443);

var app_info = vcf::get_app_info(app:'Mitel MiCollab', port:port, webapp:TRUE);

var constraints = [
  { 'max_version': '9.8.1.201', 'fixed_version' : '9.8.2.12', 'fixed_display' : '9.8 SP2 (9.8.2.12)' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
