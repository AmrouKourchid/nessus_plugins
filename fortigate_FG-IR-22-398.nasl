#TRUSTED 0051331523c134bc1bea2db6d97df091052e4809cc2dbafaef8b6d1430bbca3c238cf442d65f526dcb88b489c6dc6c293235d614e7104c13c26be248a46b008be8d59b76c557aad6294cc1d25b1696b489a6d875bdc7e4c89ae7c9762800642f50b649b61d137531169052ae0a9c3562d935066a44df7fdc0a36ff21996b06ca1403b3e4f1fb35c0ac6f9d9bf69c1db16513b405fc7597faae5e1189e1e14f37b890ab99c0cca309d3e0a1b3f5b596f48b346bc9300c12813132837074321afea2514a3dfefad5b34e36fde697b1fab302d944de0e761fd104a333e7ae86277386f878109a747aafb73e5eda638db9022874b1b156a551b309dee8b2eb277f19993360529d75c3e6d77feb64a86f25da7755b2c259713c0d5b6ac5d73a191adea903f4c0c5c1c56292c0b2363aee1ed18fb16576b11bbc6dc10d6e9cc86284e708773a5ccff9bcff04af97554b5f8e53b077d07525136b9714c3b9fe6ae3fa21ca0a3c40e23ac39e2771aff4168f43298e285c93685adc3fae38b5a0a6f89829c6d0a52687ad02a3618f885bf8cb540128805ce44b63993ce2bb8c10cc148dcabc46d0913d447988d7f8311dbdefbc16e374f5015563de0713ab4b60299dbe00693939d286d78469f0a892e2b8c4f7f859e3a409ca1922a64aac1029d7a785aece3c6f4df5378c8d34201a089dd838a23c4b50f50157199602c189394eb75f4a
#TRUST-RSA-SHA256 9a2aff19ca4a3dd9bd5ef5bd642d346d6abcfa9a8a88953bbb876293754bb802fdfaf46f59862f3a8c7c5e945be0dd1d286e7090c3d65e3406a631d593836a238c2031f9b631828bbaee8d66b82e9a1eb8afea61c61bea7b1d917f6be993c56292b4afa9e9ed1b1ec66acb4df7cd45ee328c5af7f001e01bdd6d6d3fe5e4cb6b17dfe6c2466e63fe2095d1028cc63cec51153ca51a88db9a5608902cb40f017465f6002fdd9c0f81526aafb0cc130eafd72caf5fdf2225e12e3b2c608ad4c58c105c59792a5c837bff77ccbe458deb7f997ba2f604b62e566d3410e524e9c2be30a9add222212a7016f4b3cbdc2577388a43124cd79f044a4bd072f0fe2378ba32a519d089293b1b252ca521b793ec3b42e1e05677580fe2de1e612ce0433fc1da96c176092cb3123c4d8de58452f3773dcfb85432fa3795f20b32d6db6f934cce367160ce3b4e9f8d071a8c22f501a8bf0f64bf8db6c8c3970bb94ed858d20dbec6c47afcadad9b376b92aebafed2069207e19d4371d6d15d761cdd59531c0f7705ca5d3880ae7d36b9acdeab86f486ea2bac536bf0a8fd8ecd05a798cf7cccb8ff4447082d89c3fa8d5e40da8a3bbd8e3d4197dd594a150dd015811041cf7f884d5daf4f7d049323289ee6a8c363c13863e09e79c273c9952e08f2616ddac3624db01703d5d7226ab6d54b04866b440586439d31a189943104bc5ffd271652
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(168637);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/29");

  script_cve_id("CVE-2022-42475");
  script_xref(name:"IAVA", value:"2022-A-0512-S");
  script_xref(name:"CEA-ID", value:"CEA-2022-0038");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/01/03");
  script_xref(name:"CEA-ID", value:"CEA-2023-0044");

  script_name(english:"Fortinet Fortigate Heap-based buffer overflow in sslvpnd (FG-IR-22-398)");

  script_set_attribute(attribute:"synopsis", value:
"Fortinet Firewall is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of Fortigate installed on the remote host is prior to tested version. It is, therefore, affected by a
vulnerability as referenced in the FG-IR-22-398 advisory.

  - A heap-based buffer overflow vulnerability [CWE-122] in FortiOS SSL-VPN 7.2.0 through 7.2.2, 7.0.0 through
    7.0.8, 6.4.0 through 6.4.10, 6.2.0 through 6.2.11, 6.0.15 and earlier and FortiProxy SSL-VPN 7.2.0 through
    7.2.1, 7.0.7 and earlier may allow a remote unauthenticated attacker to execute arbitrary code or commands
    via specifically crafted requests. (CVE-2022-42475)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.fortiguard.com/psirt/FG-IR-22-398");
  script_set_attribute(attribute:"solution", value:
"Please upgrade to FortiOS version 6.0.16/6.2.12/6.4.11/7.0.9/7.2.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-42475");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/12/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/12/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/12");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fortinet:fortios");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("fortinet_version.nbin");
  script_require_keys("Host/Fortigate/version", "Settings/ParanoidReport", "Host/Fortigate/model");

  exit(0);
}

include('vcf_extras_fortios.inc');

# Since there's a workaround specified in the advisory, we're making this require paranoid.
if (report_paranoia < 2) audit(AUDIT_PARANOID);

var app_name = 'Fortigate';
var app_info = vcf::get_app_info(app:app_name, kb_ver:'Host/Fortigate/version');
vcf::fortios::verify_product_and_model(product_name:app_name);

var constraints = [
  { 'min_version' : '5.0.0', 'max_version' : '5.0.14', 'fixed_version' : '6.0.16' },
  { 'min_version' : '5.2.0', 'max_version' : '5.2.15', 'fixed_version' : '6.0.16' },
  { 'min_version' : '5.4.0', 'max_version' : '5.4.13', 'fixed_version' : '6.0.16' },
  { 'min_version' : '5.6.0', 'max_version' : '5.6.14', 'fixed_version' : '6.0.16' },
  { 'min_version' : '6.0.0', 'max_version' : '6.0.15', 'fixed_version' : '6.0.16' },
  { 'min_version' : '6.2.0', 'max_version' : '6.2.11', 'fixed_version' : '6.2.12' },
  { 'min_version' : '6.4.0', 'max_version' : '6.4.10', 'fixed_version' : '6.4.11' },
  { 'min_version' : '7.0.0', 'max_version' : '7.0.8', 'fixed_version' : '7.0.9' },
  { 'min_version' : '7.2.0', 'max_version' : '7.2.2', 'fixed_version' : '7.2.3' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
