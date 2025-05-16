#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(235657);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/09");

  script_cve_id("CVE-2025-32817");
  script_xref(name:"IAVA", value:"2025-A-0319");

  script_name(english:"SonicWall Connect Tunnel Windows Client Improper Link Resolution (SNWLID-2025-0007)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an improper link resolution vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the installed SonicWall Connect Tunnel client is vulnerable to an improper
link resolution vulnerability: 

  - A Improper Link Resolution vulnerability (CWE-59) in the SonicWall Connect Tunnel Windows (32 and 64 bit) client,
    this results in unauthorized file overwrite, potentially leading to denial of service or file corruption.
    (CVE-2025-32817)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2025-0007
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c43d9042");
  script_set_attribute(attribute:"solution", value:
"Upgrade to SonicWall Connect Tunnel Client version 12.4.3.298 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-32817");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/04/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/05/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:sonicwall:connect_tunnel");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("sonicwall_connect_tunnel_installed.nbin");
  script_require_keys("installed_sw/Sonicwall Connect Tunnel");

  exit(0);
}

include('vdf.inc');

# @tvdl-content
var vuln_data = {
  'metadata': {'spec_version': '1.0'},
  'requires': [
    {'scope': 'target', 'match': {'os': 'windows'}}
  ],
  'checks': [
    {
      'product': {'name': 'Sonicwall Connect Tunnel', 'type': 'app'},
      'check_algorithm': 'default',
      'constraints': [
        {'max_version':'12.4.3.283', 'fixed_version':'12.4.3.298'}
      ]
    }
  ]
};

var result = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_WARNING);
vdf::handle_check_and_report_errors(vdf_result:result);
