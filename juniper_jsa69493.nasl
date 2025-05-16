#TRUSTED 5b932ac04f3a7d69dd80b0fa669ccd8231349e2dfd36aae97bb50fd5615e629d602fd255ec776d32b4ca16e2006a51a3bb53fac506d5f4f1e3b4ae3694d52155b00c0ed690fc7a973ebbdeb1924bd9d23824f79888b9cf1943ef080dfeb1d7e54a374a4b48a302f1b50216305846c3467f84cb0432fbed6d06f69f829a526f4fb1e63cd265bab356bb61044ec17c179ff5130ab881227935ec6184c898c058d4f0963015959722790e34ff2d13ca88c4cefc9bf10beace3c5e1a337ca64a9f775bae8dc4c79a8526af872c29773bd303da69fdef9d9d9482872acb4b78cb58f5d9895d54e2583b0fcdd9af4cbdd0783a301e12ddf570ebc519aef3b8d4a5d7fb4a0d45eac1e70fe8402268a9cd483ed4a76797de1692357054f2ebafd3f86fabcd22c01a85e18b223e4b48e9c3433dc7594ea20ee9ddcb5df55d77efedc6fbaeb926b256ec2c0303a8f3e7dfff5d4c76fc1a8d7f9eff88aad320d9f3a7b11edce5d726fd3c6065ab2bda7b46abbd2ed27717b9f154201946bd502f2819dcb6ce355f40cd031926dfb4b11d872ff6dca6a276cfe05c12537ad3655bb3522591ad813a14c70784806b9b0041da7a5eb13eaaa69c87819ab2638e1b246a7720de2245994ca4527201451014f73115f7bf63eeb9faf66d2864d0296bb49546c500a587382f0879559e81002db6f20abe51542156299306680019097e6c51229dddec
#TRUST-RSA-SHA256 5c1acb47d3decfa8bb798140c1d2d4b64178ac9d4d2e92d33bb9491ff039054cc012d971ea642be813c9f1d014406d1ea6e7ce3858101832b5e744da5f7752253361a7b4613a483e055397e0983373e81ad878738cb5f7d44fbb3ec32f2e4143c9868997a4d06aa19648b58f0c07f956de908b5dae91e3a87fca4d954ac72d729353945ce63ddb7daa1d8adedc48bfe6a0652fb7143c978d0db657119d7f38dffb1ca43421ff0d93602de023caeb08c97195f7db65a97b33ab8b62ad275cec1f40bed3ef416cafa19eed1b51fe3f52e4b19672b112533bbc39757dcb95e407f8c6f30a234ce8fc4db668e2fcba10ef85ec69aadac096045ae31d9c63f7456cf35bb70b5ab63830bbe20a256e371800e271c0025e6e3fe870a025240102be55934794e1a80244230177b86f6a7636686152a8d17c114401a06cd231e916cbd899529f1e96532c8abe15798da2cf6f8c4922471886766d3a8baa8d2c30909c1f3b28211e4085df2b6f1104de392b9a4059863a60fcdd1e181dd60f1456a7cc46c527b3c6f95af04d7ef169e9f9a1d6fc6075ee6f08802e86a864b7d661abce93dffd9c4656553914ebde7af2de458d0ae3fe48b6c07791e90fb8bec9fec4d4094a517e5ac2d8067856df9837bc7f6941b3f31040b21ddad778bc073efd6a7945682e6c6a6387ae95f3c55497b049e2f2f4383f0c649ab745a147899334682897e8
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(160076);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/18");

  script_cve_id("CVE-2022-22185");
  script_xref(name:"JSA", value:"JSA69493");
  script_xref(name:"IAVA", value:"2022-A-0162-S");

  script_name(english:"Juniper Junos OS DoS (JSA69493)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA69493
advisory.

  - A vulnerability in Juniper Networks Junos OS on SRX Series, allows a network-based unauthenticated
    attacker to cause a Denial of Service (DoS) by sending a specific fragmented packet to the device,
    resulting in a flowd process crash, which is responsible for packet forwarding. Continued receipt and
    processing of this specific packet will create a sustained DoS condition. This issue only affects SRX
    Series when 'preserve-incoming-fragment-size' feature is enabled. This issue affects Juniper Networks
    Junos OS on SRX Series: 18.3 versions prior to 18.3R3-S6; 18.4 versions prior to 18.4R3-S10; 19.1 versions
    prior to 19.1R3-S7; 19.2 versions prior to 19.2R3-S4; 19.3 versions prior to 19.3R3-S4; 19.4 versions
    prior to 19.4R3-S6; 20.1 versions prior to 20.1R3-S2; 20.2 versions prior to 20.2R3-S3; 20.3 versions
    prior to 20.3R3-S1; 20.4 versions prior to 20.4R3; 21.1 versions prior to 21.1R2-S1, 21.1R3; 21.2 versions
    prior to 21.2R2. This issue does not affect Juniper Networks Junos OS prior to 17.3R1. (CVE-2022-22185)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA69493");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA69493");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22185");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/22");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include('junos.inc');
include('junos_kb_cmd_func.inc');

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
var model = get_kb_item_or_exit('Host/Juniper/model');

check_model(model:model, flags:SRX_SERIES, exit_on_fail:TRUE);

var vuln_ranges = [
  {'min_ver':'18.3', 'fixed_ver':'18.3R3-S6'},
  {'min_ver':'18.4', 'fixed_ver':'18.4R3-S10'},
  {'min_ver':'19.1', 'fixed_ver':'19.1R3-S7'},
  {'min_ver':'19.2', 'fixed_ver':'19.2R3-S4'},
  {'min_ver':'19.3', 'fixed_ver':'19.3R3-S4'},
  {'min_ver':'19.4', 'fixed_ver':'19.4R3-S6'},
  {'min_ver':'20.1', 'fixed_ver':'20.1R3-S2'},
  {'min_ver':'20.2', 'fixed_ver':'20.2R3-S3'},
  {'min_ver':'20.3', 'fixed_ver':'20.3R3-S1'},
  {'min_ver':'20.4', 'fixed_ver':'20.4R3'},
  {'min_ver':'21.1', 'fixed_ver':'21.1R2-S1', 'fixed_display':'21.1R2-S1, 21.1R3'},
  {'min_ver':'21.2', 'fixed_ver':'21.2R2'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);

var override = TRUE;
var buf = junos_command_kb_item(cmd:'show configuration | display set');
if (buf)
{
  override = FALSE;
  if (!junos_check_config(buf:buf, pattern:"^set security flow preserve-incoming-fragment-size"))
    audit(AUDIT_OS_CONF_NOT_VULN, 'Junos OS');
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);
