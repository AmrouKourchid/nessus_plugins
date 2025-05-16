#TRUSTED 689e99cac2827e95866db6071eda81d71c3db6142fb8a606c5d32c034441725f8f205b28e676aa4c72e9d603738b21004594e473c1f06f1160d80699e9f73b75892c08a808c5456b8f10ac0f29c08aa09ac0b7a58e8d5db9cdbc069bc01efa16d8cd0bee3087aacc1a3e224d5e0ea14c5422a7606bcef5aba7703d3ca6b636bd8cc068485684e6fecac662257b52c543759826f92e55d60bdb4f96273b094a8b44cd6090a94d3363b9a3d88f5ae62ca7d69b28fe312b608cf66c3dd7f0ab66e8ff8e6f5b420736a7c3c6a623919338317851063fcb7edea75e7f7a9fd432422a794addfcbadd882afc839284c20cd9a19ea6da7e25e8c362c3e8b672109e35e6009dc2b33c1d8d2298bece2b36f246939d539ab8d1bbdf5e0d9acfe34aef5b2aa60490d34d3da85e480e4d6e6b58f22f6b636a6889ed470c30f1b68d85afbe137182c4662aceb6ec84dcc09064ee1d716c620d40d1370758aa28968d9df8615ede71173c8c4d6d3b951b3911d8a1074905c9a5b6ffd9ba329245716d5a5dcfcb19b54061fddbb5f58c54daa022dc3927833973488ebe84b19756f52d4a898ee74d79ccf6af5f30f7b32abc542651b69af341f1f322251fb410bd7bac38f0b1547f5f5b9dae7789f6da58bdea1c7122be1dae324f6ccacda954939d5f8f43a465772b4427d09698f4996823484784847e9b1ee1bcdc86eaf03cadf528d4458366
#TRUST-RSA-SHA256 396fbc46b8e5da24a497ee62bd264f6a980c634b55b288f532bb7715047db2107dbe7891a762001ea2dd75d9051079fc9775bfbba1055f292011f1a7dc1509e4e256446ad86d02bcf0e3740deda4f73ce7863582210c23680883d5b69bf83c0db6c138c68848b70ecbf11bccd49a7819c02395f5bab198cf19ba56a7c0dc77b06f2cc06622f36799d3e612fbdbf6a89f604f6f04e3429f25fde5ed29cb69196298f75613cf53fdf5bf0e80f820794ff6f68ac094993798f35fd37e6c852f3aad20ed6cb88153bdba4ae9e3d4e45c8314962eb4bf0b68132a698060315c10aac3f1b28c408e0f2ca1ab5033a82eee7be6269cdf5d61e000aaa8ff6283e9090b7593523c92a1df1bfcc8cbd34e19a37a7960c6e38247fed437784bca1fba30ff5e5b6ef827881fb7a719778ad2f92566c658a4bd888030a09108d2a42da1a996e4f5a22247187e57f784f9156b742df1d9206d30e9d7eb3e39f41b8956cabea3f6681fd07e054cd176c99de24dd4061382880ce5049ebf5cdc4f371dff38d25a94c44ab322a6f5da36a05d3151faf4ff78558cccdd0d289ff26c00d2e5a062331472ca7d9fc3740884302a3ba7d03392f9db773e6710ce8a746d0e7d07f0d2647afd15d096e8a0b292ff4606e7731fee6eb0fbae79008cd988d83ac686279e789ed94d8594c35f514b7df005713e92fd248e3a42abd44c225184527c1758e7de2d
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(125887);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/30");

  script_cve_id("CVE-2018-13383");
  script_bugtraq_id(108539);
  script_xref(name:"IAVA", value:"0001-A-0004-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/07/10");

  script_name(english:"Fortinet FortiOS < 5.6.11, 6.0.x < 6.0.5 SSL VPN Heap Buffer Overflow (FG-IR-18-388)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a heap buffer overflow condition.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of FortiOS prior to 5.6.11 or 6.0.x prior to 6.0.5. It is, therefore, affected by
a heap buffer overflow condition in the SSL VPN web portal due to improper handling of javascript href data. An
unauthenticated, remote attacker can exploit this, by convincing a user to visit a specifically crafted webpage, to
cause a denial of service condition.");
  script_set_attribute(attribute:"see_also", value:"https://www.fortiguard.com/psirt/FG-IR-18-388");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Fortinet FortiOS version to 5.6.11, 6.0.5, 6.2.0 or later. Alternatively, apply one of the workarounds
outlined in the linked advisory");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-13383");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fortinet:fortios");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("fortinet_version.nbin");
  script_require_keys("Host/Fortigate/version");

  exit(0);
}

include('vcf_extras_fortios.inc');

var app_info = vcf::get_app_info(app:'FortiOS', kb_ver:'Host/Fortigate/version');

vcf::fortios::verify_product_and_model(product_name:'FortiGate');

var constraints = [
  { 'fixed_version' : '5.6.0', 'fixed_display' : '5.6.11, 6.0.5, 6.2.0 or later' },
  { 'min_version' : '5.6.0', 'fixed_version' : '5.6.11' },
  { 'min_version' : '6.0.0', 'fixed_version':'6.0.5' }
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
  severity:SECURITY_WARNING
);
