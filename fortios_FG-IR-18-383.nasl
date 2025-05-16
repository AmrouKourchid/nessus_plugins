#TRUSTED 4470497691322dc84fe23d85f4f72ef84e181b263615bbf4e487630a7ca95a2b28ee941f8114cc066120b4f58d17e0340b18b80b82b9d9dbd6a2433e8b2e89c59b7726c8cb8a12242665de97e20c403bc2f816b80a970e1a9bfd164c88fda2ccfd8483058ff8536f421647bc4b63ee269cce2d1001310669f36e845cccca7304017d2b1e4cc01c74513efcfc50c640778d83035937a38669fe3f7199cc35edce666c722cd2a8920f1c184d434e025f8e9d98865b9ba03b33ddac2d7ccc5164bfbc1406fca65fdd46d83f3d31041c260e8ad5b8d4ad687dee838884127d948c8a1a7460d5735742ad3c25748ae73c6ff5349fb2f982673140b8c7ed15a30abcbf3bca51fa627aef2b2927bbe7d4960227ed806c889d95c776ae8061a7f5c82566bdcf7fee41413fde56c367c9555fa834b40420a1c7c3e0977a17fe2c9db5113a2f60395bdb60d1a1103e0de6bd460f2a5d407e00c0e49683396cb0d508355a2a2839023aeecb8802ba7c7c4a7e461ca29083209ed87dbe5a32084a13090d0475cc1b0e678bd2776e1348a837f26f3acc15019961da069e897a79c98ba8bd30f4e121f096bd17abad6f559fc124311a2a3a107ff915c199cbb29c7eee71741ea17927df4f5c863d0ae058280f496323beb4b22eb30553d6d9c17f054ce3ea9e2b9375756a6e46af93be53a7d21f569fbffc3503157669d6bfcf77195e6a40f873
#TRUST-RSA-SHA256 0578a407c6fda237d107a477f2ca253615dc3ae11061af24637067dc2efe4e5ee9607ecc68c540dde341af09515f0f45f851e16a99e94e35953fbf15d27ab2c7e8547ec962d572b20c78ca763f85d83b2ce7a9b52af8e2aca7493588eaeab9fc4e2d84e7e4757e82f7f859cb0d1413c1393731f04275ce1afa0f111da58812f2100f7160a3c2c9451da2bb3e738b4d8f7aba7194750e096064080bdb7e309ac7d4ff67d0175c9e506098c5e1932ec42a04e5d71ef2f7b0991bbe715c73b799dbf5fcdda8b47bfcea476b67b25884c574db22623ea3b40c5c36f09fdd6dbbf1e67b15ef552249095332b970b68cf1d5b832d6fdeb5dad255ab9a98da29264129d6d942ea8cbbc2cfc3a76af52729c8b2bdc79002fa944384ede0868875da0530d35479969888fd3efcd39a5d5d00e7305116673d807f3ee373d53a087ac5c3d33edab6175206606a63c2b016c7c2908b937e88dc7616ac40ab6dd52c75e06d6d8251a13c481e6e1b1b0cacddf3fb22914d962e065016fa931fa540ab47c5621d92fe19d923eb1ef13fee4c7ee9471c832de2271428b640b9b64d6398ffd51fd1d381f6e8c8ded968f5d3ce88f2d101a4717feb916418e3a4fa52fab2e74137b24d740935c68efb956c93ad44bbfb50b92b9a31401557d7be3898836f4bc380fc343fcf252d3f29935a800442b506b552e742c5a2c8b79c80e7be0dd0d9a58230e
##
# (C) Tenable Network Security, Inc.
##

include("compat.inc");

if (description)
{
  script_id(128278);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/30");

  script_cve_id("CVE-2018-13380");
  script_bugtraq_id(108693);
  script_xref(name:"IAVA", value:"0001-A-0003-S");

  script_name(english:"Fortinet FortiOS 5.6.0 < 5.6.8 / 6.0.x < 6.0.5 multiple pre-auth XSS vulnerabilities on SSL VPN (FG-IR-18-383)");
  script_summary(english:"Checks the version of FortiOS.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a XSS vulnerability.");
  script_set_attribute(attribute:"description", value:
"A Cross-site Scripting (XSS) vulnerability in Fortinet FortiOS
  6.0.0 to 6.0.4, 5.6.0 to 5.6.7, 5.4 and below versions under SSL
  VPN web portal allows attacker to execute unauthorized malicious
  script code via the error or message handling parameters.");
  # https://fortiguard.com/psirt/FG-IR-18-383
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2a5eaa07");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Fortinet FortiOS version to 5.6.8, 6.0.5 or 6.2.0 or later. Alternatively, apply one of the workarounds
outlined in the linked advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-13380");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fortinet:fortios");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
  { 'max_version':'5.4.12', 'fixed_display':'5.4.13, 5.6.8, 6.0.5 or 6.2.0'},
  { 'min_version':'5.6.0', 'max_version':'5.6.7', 'fixed_version':'5.6.8'},
  { 'min_version':'6.0.0', 'max_version':'6.0.4', 'fixed_version':'6.0.5'}
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
  flags:{'xss':TRUE}
);
