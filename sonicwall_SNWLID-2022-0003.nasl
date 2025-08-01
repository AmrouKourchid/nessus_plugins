#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(190934);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/08");

  script_cve_id("CVE-2022-22274");

  script_name(english:"SonicWall SonicOS Buffer Overflow (SNWLID-2022-0003)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a Buffer Overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the remote SonicWall firewall is running a version of SonicOS that is affected
by a buffer overflow vulnerability. A Stack-based buffer overflow vulnerability in SonicOS allows a remote
unauthenticated attacker to cause Denial of Service (DoS), which could cause an impacted firewall to crash.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2022-0003");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in the vendor security advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22274");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/23");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sonicwall:sonicos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("sonicwall_sonicos_installed.nbin");
  script_require_keys("installed_sw/SonicWall SonicOS");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::get_app_info(app:'SonicWall SonicOS');

var vuln_models = [
  'TZ270',
  'TZ270W',
  'TZ370',
  'TZ370W',
  'TZ470',
  'TZ470W',
  'TZ570',
  'TZ570W',
  'TZ570P',
  'TZ670',
  'NSa 2700',
  'NSa 3700',
  'NSa 4700',
  'NSa 5700',
  'NSa 6700',
  'NSsp 10700',
  'NSsp 11700',
  'NSsp 13700',
  'NSv 270',
  'NSv 470',
  'NSv 870'
];

# Cannot check for 6.5.4.4-44v-21-1452 and earlier versions
var constraints = [
  {'max_version' : '7.0.1', 'ext' : '5050', 'fixed_display' : '7.0.1-5051', 'models' : vuln_models},
  {'max_version' : '7.0.1', 'ext' : '5030', 'fixed_display' : '7.0.1-5030', 'models' : 'NSsp 15700'}
];

vcf::sonicwall_sonicos::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
