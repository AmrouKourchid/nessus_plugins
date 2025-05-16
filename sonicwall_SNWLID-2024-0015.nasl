#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(206801);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/25");

  script_cve_id("CVE-2024-40766");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/09/30");
  script_xref(name:"IAVA", value:"2024-A-0689");

  script_name(english:"SonicWall SonicOS Improper Access Control (SNWLID-2024-0015)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an improper access control vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the remote SonicWall firewall is running a version of SonicOS that is affected
by an improper access control vulnerability:

  - An improper access control vulnerability has been identified in the SonicWall SonicOS management access and SSLVPN,
    potentially leading to unauthorized resource access and in specific conditions, causing the firewall to crash.
    (CVE-2024-40766)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2024-0015");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in the vendor security advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-40766");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/08/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/09");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sonicwall:sonicos");
  script_set_attribute(attribute:"stig_severity", value:"I");
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

var gen5_vuln_models = [
  'SOHO'
];

var gen6_vuln_models = [
  'SOHOW',
  'TZ 300',
  'TZ 300W',
  'TZ 400',
  'TZ 400W',
  'TZ 500',
  'TZ 500W',
  'TZ 600',
  'NSA 2650',
  'NSA 3600',
  'NSA 3650',
  'NSA 4600',
  'NSA 4650',
  'NSA 5600',
  'NSA 5650',
  'NSA 6600',
  'NSA 6650',
  'SM 9200',
  'SM 9250',
  'SM 9400',
  'SM 9450',
  'SM 9600',
  'SM 9650',
  'TZ 300P',
  'TZ 600P',
  'SOHO 250',
  'SOHO 250W',
  'TZ 350',
  'TZ 350W'
];

var gen7_vuln_models = [
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
  'NSsp 13700'
];

var constraints = [
  {'max_version':'5.9.2.14', 'ext':'13',   'fixed_display':'5.9.2.14-13o',  'models':gen5_vuln_models},
  {'max_version':'6.5.2.8',  'ext':'2',    'fixed_display':'6.5.2.8-2n',    'models':['SM9800', 'NSsp 12400', 'NSsp 12800']},
  {'max_version':'6.5.4.15', 'ext':'116',  'fixed_display':'6.5.4.15-116n', 'models':gen6_vuln_models},
  {'max_version':'7.0.1',    'ext':'5035', 'fixed_display':'7.0.1-5035',    'models':gen7_vuln_models}
];

vcf::sonicwall_sonicos::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
