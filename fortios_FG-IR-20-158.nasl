#TRUSTED 4e282e5cbb380b1e219b619686e65cf929acb7e0a83a49f11d9996bf25604ce6e0c383f0c6c8e427f9430dd3c7ab01449cf47657bfad816dace58d662fcefd575f06463bef4974c3920635ba4a479845026ee8d0eefcb728c081a61f9ea390f5ef54bf1ec05c9f1bbcbce52d81dc39784c06de7df1f9a1536fd294f29ac01715bc4309266ce274ee0fe62b127bf7daa8e956fae44f3b72b300e4d8ca59a546c7a5d0590072ca9dec8348edb420237e73ac98b23ac85784a1c4e0642936abfd1b78a81b5e8c10e64b9606dc3744a8b6c4849ed55eb416c9c0a38d650596d508f68e0c8fe2438e5bf4510d7bf445359068f69259b31bd9a1572beb5cbca2d4ca7ffb9fff9c2af78a44bea558f4fb2f5a84729bd54939f1ca8f7cb4848d68d881d8ccea66acbac87db996a4a3598ae3be83dcd44e4ea36038e01476703d407d9dd5005a0be81bb0b4244c3354c9679813486f0a996d36843024b68700795d7b033ec0f02a367c76559acba17dcb851b8348671707aa0af8344b2e69cdd89723972a4d301cc37f6d7ee7b366bfb7c0192c0367b9196bafc5d26c381cac714ab1600377443b6f0130b7c78743465244988c99c2175b39b126d8affd91a56d76fac6a096975a701c014122d910b87d0d6799559236b5ef640c36e6c91424f41a90a3e88d47d2df6c340e9b76d7ed76251ad11e3e0719fceed875c14a8fdd7fe3640fe6
#TRUST-RSA-SHA256 575a4e323c0e31dda969382e7b791bc502273dae6a933e8d9b31a0a41c65042eb911ebb3148396b9a9d1c1306a95f17be13e6002ecf4135a551e2a92c627403459d85afdfaf2bd2145036d8168ea3aa5fa3ffee111e68d411f7c52a0bb9b76d57cb05c6a970dfba354215790c7528a469c335580371c39eee2433a881023bbfaa59d40aafdc9b46010040ce89c72e6ef5885d0950e253bfeb3e4f52b92426a3cc0e9e54e23928829da9436f24867d00125462c08057d024802fc9fa4fabcbb8c2ca2547337dbc22c897521aaded37f88c3d0957a80b8e094a87970119a2782ae247003c30a9c56eee4cfb37a2fd351497a21034ca677bdb90979f4d0fbd3213547e10e1bf89bc41031a179432c83b0c1a32bdde0e70ce7b1361e167a0ea60d6019ca33ede17867b0d8a953ba67f6b57758caac8df82c6cd37faa8e04f026f8ed46a84706e163b356f17a2e249ce3009c77c0d13c11170265ba964b381ac75241519c060567751be5d09c807ecbc00b864ab534ccf78e8a8b8dc2ad16aa1384f31f5ef0632c2e7b7500948e0f4b759607c9102e0098fd4ca4d001cad5a789c6cccbcf35d5c3593426746b924e5c7fbb00e85ae32238d857d2aff89ae011234446790e932eb3661cb68e893120e53c817fb7ecf85efdf75a912164b0f2125534e9eb551d2b956a89fc284ad8a2b0e690d37ca5216d1c57f3957a4bdbcf68b79ea3
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156754);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/30");

  script_cve_id("CVE-2021-26103");
  script_xref(name:"IAVA", value:"2021-A-0574-S");

  script_name(english:"Fortinet FortiOS CSRF (FG-IR-20-158)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a cross-site request forgery vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of FortiOS that is 5.6.x, 6.0.x, 6.2.x prior or equal to 6.2.9, 6.4.x prior or 
equal to 6.4.6, 7.0.0. It is, therefore, affected by a cross-site request forgery vulnerability in the user interface 
of FortiGate SSL VPN portal, which may allow a remote, unauthenticated attacker to conduct a cross-site request forgery 
(CSRF) attack . Only SSL VPN in web mode or full mode are impacted by this vulnerability.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.fortiguard.com/psirt/FG-IR-20-158");
  script_set_attribute(attribute:"solution", value:
"See vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-26103");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fortinet:fortios");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("fortinet_version.nbin");
  script_require_keys("Host/Fortigate/version", "Host/Fortigate/model");

  exit(0);
}

include('vcf_extras_fortios.inc');

var app_name = 'FortiOS';
var app_info = vcf::get_app_info(app:app_name, kb_ver:'Host/Fortigate/version');

vcf::fortios::verify_product_and_model(product_name:'FortiGate');

var constraints = [
  { 'min_version': '5.6', 'fixed_version' : '6.2.10' },
  { 'min_version': '6.4', 'fixed_version' : '6.4.7' },
  { 'min_version': '7.0', 'fixed_version' : '7.0.1' },
];

# Only SSL-VPN web-mode is impacted. Disabling SSL-VPN entirely or disabling web-mode are valid workarounds
# diagnose sys top <Delay_in_seconds> <Maximum_lines_to_display> <Iterations_to_run>
# We want to make sure we see all processes and only display it once
# If sslvpnd is not running, host is not currently vulnerable
var workarounds = [
  {config_command:'diagnose sys top 1 200 1', config_value:'sslvpnd', misc_cmd:TRUE},
  {config_command:'full-configuration', config_value:'set web-mode enable'}
];

vcf::fortios::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  workarounds:workarounds,
  not_equal:TRUE,
  severity:SECURITY_WARNING,
  flags:{'xsrf':TRUE}
);
