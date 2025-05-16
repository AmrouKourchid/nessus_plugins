#TRUSTED 53c7ef60c06a7d75869917cc958d60877dc365040a94d8f2e3d33f3f9c490d3e26f5fdaa36b17c5aeba3bcbe7fa925f122b8770fe1518e8ae6bcdd64047d453b84f0b91e8f2f10d95f3e9acfcf69591af84d1769720ef67563ca8cce0f6f611d544a59a18e680d602bfc53da3922008229b136c6519825d016a60c793fc51247f931087c4e337f24161586cfecaa47d2f4bb8be78318228870fcf6153b657423d6aa40ba2682f4a0b52516b9cbe9546c7360d5da4cce2c2d69fd757776f90f2590cd69d5110950ebe387ca51d5b2fe19be9a1de355bbc741e5ba73cd0241e95da3d60dad8dd8985c83605fd34fb797345dcd995cac48a094c0d92394df05e87fb2027aa3f7e434b716a8180af24780eb849a48e5ecffa8ae10b07d6a2b4fa132b7cfa10d89f4318575dd69cb8ef7f403f49083227dceafee9d74a995ee96f52fc4521332f27de8c8ed93c9df6e9bfb3cc4d2bb2b53ee268867a802b748def99a388851356099560c1e5aeeb58c40df79adc8b7ea05ad2974bf3a6016389be25c4c0b154ab647d9a8e9aa0f261a4335949bf92be3da6cc8370f34267f5c6530723d1f8bc762c4cb50eb1b7f57ee16d98a42987f1a4db60cc8788ed5316feb341fe17db2a1f19073fcc66c8b96ea3fb5c7d1795b8f3df69459d5a839a65776231b3eaefc015ba463a6e61dabb856729bdc9356539bded8d1694c4c5b6f8740ed0a
#TRUST-RSA-SHA256 7013ced10849049f6b9d179da6ca8b5d018800af276c3569562a4de264d7ebb53822d05947eb54b4f4a26496e22b57ff07aa230fdc1608bfeb7ae1e65de24cdfe1f057c16e6b81dd96a18e08baa91772ab9e5161f0d09dd95d9de57c00fda20de3b1d642009448c4a496465220efaf7d30b9a42accff4fbc935f661da9c60af7c920a0a7a1513be4ab80c02a227ace7f4a53b50b033340559ce01c3e7d8e6ca7383ea42886ab432a45682ecbafb82a119691e87da40a50c63a96aac56d8204ce261e0935313dc798d0f1f0d165cc73f0947549a57380afc1349295079fa97bd4bf2c0efb02600a132103746d6e84e7844905ff7fe6810bf4a76544684dcbb323a876e4c88f867f4806b2c0bf3ada4955843af39f340fcf65e67dc15e84fca0ab982b1f46505a394a5537b9ae6bf827cc40f5296ce25508d7d3819b3e75f1ba8c0ba15d98e060f75b9da2be849089a252607b990a45667d2ea35e50ce4b9b25e05649a96509c72455ea12f6f784f03c377055bf57779d75b48aa6d4d012f233c94c39edac213e1d2154d10f833e24d55b6b4765a93d2807f16af5e7ccf1dcab6d2134a462c550f8569c4f4e53757aba53da0ed14cd4396bc455d666816f8cbec251ffa7e9967aab1aca1bbd6935c3497d1f2f6542919297b2c09268befef4a9dadb4ff5f36c1301244d91d498172f97d5e3257b1d85a507a41867318cb9a75dbf
##
# (C) Tenable Network Security, Inc.
##

include("compat.inc");

if (description)
{
  script_id(125889);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/30");

  script_cve_id("CVE-2018-13384");
  script_bugtraq_id(108454);

  script_name(english:"Fortinet FortiOS < 5.2.15, 5.4.0 < 6.0.5 SSL VPN web portal Host Header Redirection (FG-IR-19-002)");
  script_summary(english:"Checks the version of FortiOS.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a host header redirection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of FortiOS prior to 5.2.15 or 5.4.0 prior to 6.0.5. It is, therefore, affected by
a host header redirection vulnerability in the SSL VPN web portal due to a failure to properly validate HTTP request
headers. An unauthenticated, remote attacker can exploit this, via a specially crafted HTTP request to redirect SSL VPN
web portal users to arbitrary web domains.");
  # https://fortiguard.com/psirt/FG-IR-19-002
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4ee519b5");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Fortinet FortiOS version to 5.2.15, 6.0.5 or 6.2.0 or later. Alternatively, apply one of the workarounds
outlined in the linked advisory");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-13384");

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

var app_name = 'FortiOS';
var app_info = vcf::get_app_info(app:app_name, kb_ver:'Host/Fortigate/version');

vcf::fortios::verify_product_and_model(product_name:'FortiGate');

var constraints = [
  { 'fixed_version' : '5.2.0', 'fixed_display' : '5.2.15, 6.0.5, 6.2.0 or later'},
  { 'min_version' : '5.2.0', 'fixed_version' : '5.2.15'},
  { 'min_version' : '5.4.0', 'fixed_version' : '6.0.5'}
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

