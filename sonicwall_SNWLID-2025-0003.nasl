#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(232198);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/06");

  script_cve_id("CVE-2024-40762", "CVE-2024-53704", "CVE-2024-53705");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2025/03/11");

  script_name(english:"SonicWall SonicOS Multiple Vulnerabilities (SNWLID-2025-0003)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the remote SonicWall firewall is running a version of SonicOS that is affected
by multiple vulnerabilities:

  - Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG) in the SonicOS SSLVPN authentication
    token generator that, in certain cases, can be predicted by an attacker potentially resulting in
    authentication bypass. (CVE-2024-40762)

  - An Improper Authentication vulnerability in the SSLVPN authentication mechanism allows a remote attacker
    to bypass authentication. (CVE-2024-53704)

  - A Server-Side Request Forgery vulnerability in the SonicOS SSH management interface allows a remote
    attacker to establish a TCP connection to an IP address on any port when the user is logged in to the firewall. (CVE-2024-53705)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2025-0003");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in the vendor security advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-53704");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/01/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/01/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/06");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sonicwall:sonicos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("sonicwall_sonicos_installed.nbin");
  script_require_keys("installed_sw/SonicWall SonicOS");

  exit(0);
}

include('vcf_extras.inc');

var app_info = vcf::get_app_info(app:'SonicWall SonicOS');

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
  'NSsp 13700',
  'NSsp 15700'
];

var constraints = [
  { 'min_version':'7.1.0',  'max_version':'7.1.2',  'fixed_display':'7.1.3-7015', 'models':gen7_vuln_models },
  { 'equal':'7.1.3', 'ext':'7015',                  'fixed_display':'7.1.3-7015', 'models':gen7_vuln_models },
  { 'equal':'8.0.0', 'ext':'8037',                  'fixed_display':'8.0.0-8037', 'models':['TZ80'] }
];

vcf::sonicwall_sonicos::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
