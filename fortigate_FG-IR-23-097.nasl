#TRUSTED 687d3759d26e0c75f574fc6e62c4ac190e8b3e46930ffb11fad9ff3a9f03930c70e1b995bc1bf7638411bef45c6619adb5c662cd85ba00ad52d54bc9c1d683938aa5ce9ee3f410860a7fc868f3d677f10b215105277417ab2e7187f539840d24cf9b425966bd5caaeef01d3986d9e33b82dfcb98f91261f3bc17d2e43a83f88af8e08085c67e012e73f2434351552806dac78d2978766edf9b51b0cd2692274efdf290a9c89ee478e4588ee83daaa18d5c3f6a47ca05137bcb4721246598b547ff4e4305cbfd6218a01f185d8461c8d991e25073d755925fd634b3ae3012e392c274e596ec76e826475dfafe87f19e648b006391c9002d58b224beea3a457d75b6a419c1b68365e2e24532e322ba68752a98e011e7b2c6c299522ceaac2696f3cadd91152d8d41dfa06e610ed4e9ab49f0facfcb2229d300b51a07052c1d6a91748e726d10778e5233ed52fba61a7ca721a4309ba3e74c4e0d868c42e33b6eaa5f418690e91f106b4864e8a38ee856aec67377c7403ba5f450fb2faef1111c76c65c0c0cc9e9dc1583402670cdfb68e060f6eb0cb0bba79ea324efaf8c579bd8b0415c8c527eec774162f87b95f5a7fbbf5019471c6f38faa4d7ccaa9684abc4cef66c0bb2e1118c8600b78df084e7b66f8150d7e8fab83ea97cf26f69393de9e3114f54969ad94ed92d05049e83b553a4729555a1d8f78531a1d6a6c1f0f80b
#TRUST-RSA-SHA256 652918f69cd18a4a16b6a09db668e111b4011a7c4af5e789f23e11ef4299b4885523bb847afcdb50821eb2beb7e42bf8a6f747a0e46ded8057a6fcf0b6f888f278c4cf5c6b085b9f15e61046d47c4e4f2e5b598afeeaa7966ea1c8cb1b9dc1ccc00fff301b5eae60d206bbaf06752df27c7b3cf983014c2d201226a85a7491b3edd874e5f716ca8772d29a50d02ec4fa1d3ffb196f6a879093344a2ac6004dbf8c58f8f7704c4203b4f119780b01e4e208f0d86eb5d420fc290d29e08a64694de45fdd81c2b461d75aca607b61a845ad0e72342b3a72298f236f695a1767e42e58ae4935b086655d388a30a2b47985c25fb7a5b634256717ef4c4735e3373ec1b575cd01ea900c02cad507258762eb712236fd40995865eeaaa9ffbcf5591003630889769ab3e08c5be31ad0820fdd6a69403991c3fb99ccf0d9be72d6bf7cc15e366cbc6a07d85e4073abeba8e9bfbf2f704f9030dcc23b6a014b3af0c6f74d659a4d4f40ca4e2dc7a7b49ef93b1b382539543294736f213e454bf3792249aff7b4fbc8acab6d9ff1d701a205166b7c10817e424f0d9bceaab08bc299d81904abfa4a723aac6fdd3f64958f5cc5035b40f1a0eb220bc40cf0e7ed9c9ddcbf623ba9de9166545be13adc0490f8433910a9963880c3e2a2fd672ae8047e403baa1c64ce0580f235e5680a1160e9ac9ca6905a523d1ed7667c44b2fa9150c09c30
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(177116);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/29");

  script_cve_id("CVE-2023-27997");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/07/04");
  script_xref(name:"CEA-ID", value:"CEA-2023-0020");
  script_xref(name:"IAVA", value:"2023-A-0281-S");

  script_name(english:"Fortinet Fortigate Heap buffer overflow in sslvpn pre-authentication (FG-IR-23-097)");

  script_set_attribute(attribute:"synopsis", value:
"Fortinet Firewall is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of Fortigate installed on the remote host is prior to tested version. It is, therefore, affected by a
vulnerability as referenced in the FG-IR-23-097 advisory.

  - A heap-based buffer overflow vulnerability [CWE-122] in FortiOS version 7.2.4 and below, version 7.0.11
    and below, version 6.4.12 and below, version 6.0.16 and below and FortiProxy version 7.2.3 and below,
    version 7.0.9 and below, version 2.0.12 and below, version 1.2 all versions, version 1.1 all versions SSL-
    VPN may allow a remote attacker to execute arbitrary code or commands via specifically crafted requests.
    (CVE-2023-27997)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.fortiguard.com/psirt/FG-IR-23-097");
  script_set_attribute(attribute:"solution", value:
"Please upgrade to FortiProxy version 2.0.13/7.0.10/7.2.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-27997");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/06/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/12");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fortinet:fortios");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("fortinet_version.nbin");
  script_require_keys("Host/Fortigate/model", "Host/Fortigate/version", "Settings/ParanoidReport");

  exit(0);
}

include('vcf_extras_fortios.inc');

# Since there's a workaround specified in the advisory, we're making this require paranoid.
if (report_paranoia < 2) audit(AUDIT_PARANOID);

var app_name = 'Fortigate';
var app_info = vcf::get_app_info(app:app_name, kb_ver:'Host/Fortigate/version');
vcf::fortios::verify_product_and_model(product_name:app_name);

var constraints = [
  { 'min_version' : '6.0.0', 'max_version' : '6.0.16', 'fixed_version' : '6.0.17' },
  { 'min_version' : '6.2.0', 'max_version' : '6.2.13', 'fixed_version' : '6.2.14' },
  { 'min_version' : '6.4.0', 'max_version' : '6.4.12', 'fixed_version' : '6.4.13' },
  { 'min_version' : '7.0.0', 'max_version' : '7.0.11', 'fixed_version' : '7.0.12' },
  { 'min_version' : '7.2.0', 'max_version' : '7.2.4', 'fixed_version' : '7.2.5' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
