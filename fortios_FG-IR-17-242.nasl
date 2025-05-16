#TRUSTED 50846dcd5f61fef25e14debe33cf74f0bebac65207053b422ec0d6dc7a0f782c481b857f3cd38dd49548054f37d0a99d9408d423dd2e3fb524f973ca222b14e7d639def720fe5a65b2058ab8dca64dc9ba2f7a5e95e9fe96884ed13a5337e7ec9b156c45c38cca3a01b0efb4134b068b85ca80f4730552859e818e8c2b93512573c42e4457e6da74e9e2ea88470024da29dc5b786684adef0beb3eefdc523e51d5577c628cd47dbc2f290f336b5f33943077dadb9bf97ad5056f1c023b437a78b0296dca4df16eeebd6f84ccf139d049f3cb8921a1653251d7ce8fd1c7ea527e84b312f74c23bcb07c52a4b720ebee91b40898a7f43fe79c9d91c8f827661e316dc079b8f2b0996f58420f3c3a145ed274c0cf8cbe4f9dca00e078de1b04f589fa0fbef5325c0123f213069546536b6162361ac30b02dbcb9a0c44ad7e9671ec2916fb953c07611334605290727e89a34aedd389b7528f7c689bb6ee412fb29c0759f4e86def482f66c4a0342946844bbcf3844a55e08f272d76ae55d386f9e266ea2a51f5b4f2a4da4e22f70232589539d1c7cc01e0cecf1066ee7104bc203e134931793d3b4afda0bfe0605f00b1703c2d2617fa6ebd5f6de7c0cc3ac785df6edc342ab7996dab6505bd76af8aa56e48b7ab0b1971bf0234f4021880fc040c3439d4b6f2cf97f8ad550b7595451bce7d5f325674376265cdf0971c64a2e847
#TRUST-RSA-SHA256 630251a417809f456f5ff1a9b97220d19d61169bc6a0ba2e382eecd4d38ea614b6ff7940e863936c63f9ee1d942b914d6786aec2412e0bd27c362b4f2c3dd97964e2caed8cf63ce00e7249be4a9c6d6d598c699d2088f027683411564f1a19f9912c089e8ccc7e122f05145a08e5c0e74ad2a2776e0ce229077d1239dd53d9ca3b26b0f5e93c968190ee66e76a58d5cc4766957ada2f496a8e084990723fde90ee58f4a38be94067f955d60a6e1bbd1f4379e6f0d935f1b849db2e408cc7ff84425b463b02bb040d0074698ec8ad029bdc377d785e90576986e3864cdafb610a3e107459d56da4c3dd31664df4b87e3d3b1993ca0321b6ec194e955cc1085bbd50a8e159f1c0a0a6a20ceb70f80c30c6fbb5bc66b722581b12eb17a2054634b2d0caf99f087d29af332227501b324129eff00d36c72d32a9c32264fa2ea90a940b5039e516103d5be05c72cbe6c2d23d3d1ece1665e7a487622b0052a155a584f8a7e762ffb86d53b5d2083c8e15020e416fc17b9d17a12b6cf292b132cd0e40a045d8d2081f734414d5a65fd34fdf2fda1ec25129728262129061352d075a70031ba1d4515bc5f4babc4c6f7f8608fa3893e6f06582562c2896cc1ea41b1c4a064ac0a0e32c4fb10617c56723e35281a4eb191237ada6b506746680c9bc865464e7eb9a31e71b7f882797fd92c41216f67b3dda1c6dfeb0880c662b317200b9
##
# (C) Tenable Network Security, Inc.
##

include("compat.inc");

if (description)
{
  script_id(104886);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/30");

  script_cve_id("CVE-2017-14186");
  script_bugtraq_id(101955);

  script_name(english:"Fortinet FortiOS <= 5.4 / 5.6.x < 5.6.8 / 6.0.x < 6.0.5 SSL VPN Web Portal login redir XSS (FG-IR-17-242)");
  script_summary(english:"Checks the version of FortiOS.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Fortinet FortiOS running on the remote host is prior or equal to 5.4, 5.6.x prior to 5.6.8, or 6.0.x
prior to 6.0.5. It is, therefore, affected by a cross-site scripting (XSS) vulnerability in the SSL VPN web portal due
to a failure to sanitize the login redir parameter. An unauthenticated, remote attacker can exploit this, by convincing
a user to click on a specially crafted URL, to execute arbitrary script code in a user's browser session or to redirect 
the user to a malicious website.");
  script_set_attribute(attribute:"see_also", value:"https://www.fortiguard.com/psirt/FG-IR-17-242");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Fortinet FortiOS version 5.6.8 / 6.0.5 / 6.2.0 or later. Alternatively, apply one of the workarounds
outlined in the linked advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-14186");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fortinet:fortios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2017-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("fortinet_version.nbin");
  script_require_keys("Host/Fortigate/model", "Host/Fortigate/version");

  exit(0);
}

include('vcf_extras_fortios.inc');

var app_info = vcf::get_app_info(app:'FortiOS', kb_ver:'Host/Fortigate/version');

vcf::fortios::verify_product_and_model(product_name:'FortiGate');

var constraints = [
  { 'max_version' : '5.4', 'fixed_display' : '5.6.8 / 6.0.5 / 6.2.0 or later' },
  { 'min_version' : '5.6.0', 'fixed_version' : '5.6.8' },
  { 'min_version' : '6.0.0', 'fixed_version' : '6.0.5' }
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
  severity:SECURITY_WARNING,
  flags:{xss:true}
);

