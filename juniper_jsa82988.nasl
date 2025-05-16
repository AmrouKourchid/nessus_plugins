#TRUSTED ae0ac766e06bce266428ffb93aa44b0713d632275ccd4345cb451a18d6fa865655183576325428a638d2f65b17401678b83c519dc4c5ba0538d3748c29eb5f1b062fc6d0f7b67ff69df451ec24e78061d0a3ee58e43b6703265459db7aa4f3c40433c63bf6f298df198fc99375eca5269eec153385e9da1dc2f53e2cdcbae4bfc9f952c00327836df600e92a1ea780b6a155e6ccbcfbf6b9739e2cd8ca39b6ea114de8d2018edc59bbb3b84b76da15669efff8771a822bc4ed0fc0976c66360204ca011d0affbaee2452364c7adafaded60daa5ac9bde8b60560df68e279de81f3caba5435b764947ed79ea19c6d75648f5525bf24c19dbb95f8afbfaf496558cc69dd8a494689f9a6ef63b1dc674b58ba06870a692b39a0036f4a81b0dfbbc7c8294b17739bd76568ac03e6feb27b0f1d830bbadfc688fd154548bc603cec2999285e3a0d1b53d9e544e1ec9bd59f16b35ebbabe22560606aab0a132a93203ffb6012e5c60c1d19cea0ef2271fc8d9cbf09104fa7d9f728d80fc276166019b7b37f71115c3f19947640256e7c8da3cb428b5cd2f0efc3705b63b793be5b3762e043598c96e70539b90a28305f9adedec84e14470a61831281917210f7463c89a0e140fd4ba010483964daa4c3b2bea68533580d0a2d73f3e92d7a042fbe18ffaeadecbaa61ce05bb7d2dac59051417c80f518e030678d331c8db85a5807d326
#TRUST-RSA-SHA256 3491d439c20a45dfa985f107bf494031bf70dd9c9f7136e156e67d31ae30e3765faf037a1bb117922107284911097bffbfadb098ed8f7be064c7610e46d20289a2ea348cdce2030fd81d5d8198e14c58b3cd2cfe964a2aba1c941a4097e92789669d6e0fa9d1b544f1d6a0e01fe8d2d6c2deae02533a972a9b1a209c74c5c798a5d72c1e81a7cdadd1daa133af4a3bffeaf6997488bd8bfe09e55d6538b93f30004224c3dd5403230c9dfaff152880c468a2eeeecc84467fb49eba8728112a96c94191af085cca8592b8fd9d00f4b68deb58df34eb5fe2bd75a7efbf1598f238671b957169d58611836156212f13716668372c88e514e50c1f74bd7b83625c37323fd8844ec8402763f295b3cc2283470769b98522f8307b632907361bda1ff53979b2027afc80fc4ac56ee8e183e7ecc6b3929edad45176aa6e7d0d719bf5f81de9177e15e32d562ac098fca4053cfcd97d8c0ec0126ea8e3634612b1dbc005918c15734fdfa80402ab462f1a4b1ba0e65fb4305c699af654454c34ac9d97c3fc159d82bd755a696c6fe19288558af14cd5122a76db3c5cba505590a3de09eea6cc4622da8211923c24a081f74c66bbca2ec8c813530ae180bda96f7b8382f34533e346c7e8914e6118083fde7c7b9d5ffec26f0e560b1861f5acc7f4f6778fb44715ec83e8d7ee2eeb77bb34d1e0aea975940a7386afd724312c23f44d1560
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(206272);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/29");

  script_cve_id("CVE-2024-39529");
  script_xref(name:"JSA", value:"JSA82988");
  script_xref(name:"IAVA", value:"2024-A-0385");

  script_name(english:"Juniper Junos OS DoS (JSA82988)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA82988
advisory.

  - A Use of Externally-Controlled Format String vulnerability in the Packet Forwarding Engine (PFE) of
    Juniper Networks Junos OS on SRX Series allows an unauthenticated, network-based attacker to cause a
    Denial-of-Service (DoS). (CVE-2024-39529)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://supportportal.juniper.net/s/article/2024-07-Security-Bulletin-Junos-OS-SRX-Series-If-DNS-traceoptions-are-configured-in-a-DGA-or-tunnel-detection-scenario-specific-DNS-traffic-leads-to-a-PFE-crash-CVE-2024-39529
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f9500093");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA82988");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-39529");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/28");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  { 'min_ver':'0.0', 'fixed_ver':'21.4R3-S6' },
  { 'min_ver':'22.2', 'fixed_ver':'22.2R3-S3' },
  { 'min_ver':'22.3', 'fixed_ver':'22.3R3-S3' },
  { 'min_ver':'22.4', 'fixed_ver':'22.4R3' },
  { 'min_ver':'23.2', 'fixed_ver':'23.2R2' }
];

var override = TRUE;
var buf = junos_command_kb_item(cmd:'show configuration | display set');
if (buf)
{
  # Configuration details from the advisory
  # =======================================
  # To be exposed to this issue at least one of DGA or tunnel detection needs to be configured:
  #
  #   [ services security-metadata-streaming policy <name> dns detections dga ]
  #   [ services security-metadata-streaming policy <name> dns detections tunneling ]
  #
  # and DNS traceoptions have to be configured:
  #
  #   [ services dns-filtering traceoptions ... ]

  var conf1 = junos_check_config(buf:buf, pattern:"^set services security-metadata-streaming policy .* dns detections dga");
  var conf2 = junos_check_config(buf:buf, pattern:"^set services security-metadata-streaming policy .* dns detections tunneling");
  var conf3 = junos_check_config(buf:buf, pattern:"^set services dns-filtering traceoptions");

  if (!(conf1 || conf2) || !conf3)
    audit(AUDIT_OS_CONF_NOT_VULN, 'Junos OS');
  override = FALSE;
}

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_HOLE);
