#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, inc.
##

include('compat.inc');

if (description)
{
  script_id(198221);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/19");

  script_cve_id("CVE-2024-2301");
  script_xref(name:"HP", value:"HPSBPI03940");
  script_xref(name:"IAVA", value:"2024-A-0311");

  script_name(english:"HP LaserJet Printers XSS (HPSBPI03940)");

  script_set_attribute(attribute:"synopsis", value:
"The remote printer is affected by a Cross-Site Scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"Certain HP LaserJet Pro devices are potentially vulnerable to a Cross-Site Scripting (XSS) attack via the web
management interface of the device.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://support.hp.com/us-en/document/ish_10617756-10617781-16/hpsbpi03940
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7c8e043f");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the HP LaserJet firmware referenced in the advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-2301");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/31");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:hp:laserjet");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("hp_laserjet_detect.nasl");
  script_require_keys("www/hp_laserjet");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include('http.inc');
include('vcf_extras.inc');

var app_info = vcf::hp_laserjet::get_app_info(source:'fw');

# if its not one of these models, its not affected.
var affected_models = make_list(
  "CZ181A", "CZ182A", "CZ187A", "CZ183A", "CZ172A",
  "CZ173A", "CZ176A", "CZ177A", "CZ178A", "CZ174A",
  "CZ175A", "CZ184A", "CZ185A", "CZ186A"
);

var constraints = [
  { 'models': affected_models, 'fixed_version': '20230330' }
];

vcf::hp_laserjet::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING,
    flags:{xss:TRUE}
);
