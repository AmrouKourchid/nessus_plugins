#TRUSTED 75336adffb17605a110ebfe60a151462ad9905eaf29c5b81d9cc4c5bce6e28f49c71fef33d1961e5367e01dba91b34e0982ebc5f18e1d6a927c98daa94b38b0affa40bd4f8362cc99396f01f355dd29cdece9cc94889d8c19718492e216c27c339db56d20d412ffb284c06c9a6057cccdfdb51f31b57e9944f06915ee36fbe842a9edf865f276c6f61394b8fd119ed32fbd0d5aeacf8ff1c2afb7fbdd4629d0ed008f57ff5aae0d7030139c0fc8a6d68f5446db7c834bc67c989b3a1ed0c804aabf1f39afb519afee3343da21561b3ca507ac0d7ba62de90602728d81f04c09023eba9d55975c6c8ff7a8cdf07d20e98c2885415e54833eba7270c15b20847b5b99c28d7a82cdf0331e0208ff011c0998a8a041b65d72e90cff3dfcb234e66aed7bf14af56d48d867ef601c8fe6848946444acc17c6779de1c0779afede5901eaee1382a4d7a98751759b6fc66b3ac57fabe415f088373078fb219626dcc5a8b82fb779fa7b33c92155a70c3fe24c07e3ba3a6a8a52c8c1bc333944dea4ed6d6622f740c10a93c2a8e56620ee52244688ecf24fefccc80bc8d0dd254886ba9497ea03231bc0c61467024a7c5c33956a3eada513e2bd7c93ecbe20e7df86d429bd31a72721b58e36b1e13e9c63d806c53b344cb46442cf920fac9d33d2a4b53de7319b8fb1821f559594daa8c6cc71f32ff621319bccc4054254c2431e7f47b2c
#TRUST-RSA-SHA256 121ef2f990083f7605d327bedfe16f300077d902bdd9790c49b1cf9847db1a8d25fda4715c0a8001393d9cdb68bc35ba44aac04da7b417126491bc3848c9f7a81406139dca3af062282ec5a64fe44495b48217c4928573c43f45baeca65966f25df893d3683da94faf892c3fb9806be1f3a579c5299a532cd6d101ec4ffe3c9ca6ddbc9ec70d18a96a560a91217b9e4ce324fd56c2ae091063ed6ff3ffc95e7f2e952df7125a6db98ca1396f21483e3fecf35b316acc9d684f19d80f0d60d2431768e51b4099374275bacf1b2eb77b1423d2e21d4074e893099f7bbc2218e7121f5d5034f85a1dbfa9d0401e0799ce391a12c66e6f8820b779a43ed4e319c043efb7da8af6235a7c20aa743b7c6fcd739b7cfc9a961071d9c58934e8e6f55c8ffaf345641f11702a8e4d0fef9ae4adb3acb311876a1797876d9d1f38e4470698022d8eb138e7ec699e80382737469b30ce799d177e38950f79f84b496b9fe86522753cc8741f80548653be36e721a0f6bac23321c403679e0e3f46954d0b15cb6e69e276ae256f0393315a8f152a8333a77ebd891106a6fe6be9419ba3e9b897c480f4da3b70e8579e2733b80360dc69febed02a76e9ac93ad59e0568d60f41a0f4328781a71757a47f90bfd7a0824a925d26055f56291c25e1905ae9bcc79de14f9f7bb988e1637edc9a90dfce1c94e7b423e9ab39dadc89ea6341603aa2a80
##
# (C) Tenable Network Security, Inc.
##

include("compat.inc");

if (description)
{
  script_id(125886);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/30");

  script_cve_id("CVE-2018-13381");
  script_bugtraq_id(108440);

  script_name(english:"Fortinet FortiOS <= 5.4, 5.6.x < 5.6.8, 6.0.x < 6.0.5 SSL VPN Buffer Overflow (FG-IR-18-387)");
  script_summary(english:"Checks the version of FortiOS.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a buffer overflow condition.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of FortiOS prior or equal to 5.4, 5.6.x prior to 5.6.8 or 6.0.x prior to 6.0.5. It 
is, therefore, affected by a buffer overflow condition in the SSL-VPN web portal, due to a failure to properly parse
message payloads. An unauthenticated attacker can exploit this, via a specially crafted request to cause a denial of
service condition.");
  # https://fortiguard.com/psirt/FG-IR-18-387
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ffaddea9");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Fortinet FortiOS version to 5.6.8, 6.0.5, 6.2.0 or later. Alternatively, apply one of the workarounds
outlined in the linked advisory");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-13381");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fortinet:fortios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("fortinet_version.nbin");
  script_require_keys("Host/Fortigate/version", "Host/Fortigate/model");

  exit(0);
}

include('vcf_extras_fortios.inc');

var app_info = vcf::get_app_info(app:'FortiOS', kb_ver:'Host/Fortigate/version');

vcf::fortios::verify_product_and_model(product_name:'FortiGate');

var constraints = [
  { 'max_version':'5.4', 'fixed_display':'5.6.8, 6.0.5, 6.2.0 or later' },
  { 'min_version':'5.6.0', 'fixed_version':'5.6.8'},
  { 'min_version':'6.0.0', 'fixed_version':'6.0.5'}
];

# Only hosts that have SSL-VPN web portal enabled are impacted. Disabling SSL-VPN entirely or disabling the web portal are valid workarounds
# diagnose sys top <Delay_in_seconds> <Maximum_lines_to_display> <Iterations_to_run>
# We want to make sure we see all processes and only display it once
# If sslvpnd is not running, host is not currently vulnerable
var workarounds = [
  {config_command:'diagnose sys top 1 200 1', config_value:'sslvpnd', misc_cmd:TRUE}
];

# source-interface only exists in the configuration above 5.2 and above
if (ver_compare(ver:app_info.version, fix:'5.2.0', strict:FALSE) >= 0)
  append_element(var:workarounds, value:{config_command:'full-configuration vpn ssl settings', config_value:'set source-interface'});
else
  append_element(var:workarounds, value:{config_command:'full-configuration vpn ssl settings', config_value:'set sslvpn-enable enable'});

vcf::fortios::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  workarounds:workarounds,
  not_equal:TRUE,
  show_check:'config vpn ssl settings',
  severity:SECURITY_WARNING
);
