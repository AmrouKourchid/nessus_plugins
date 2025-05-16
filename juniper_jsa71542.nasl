#TRUSTED 713f9a2a9e18a82b44edb852fc4a6576e8e273de4899e4609baa258452129798f4d40f2c628d3ce6784e7518e9bbcb5069b963111d0f65e23d82de9c567716322b7ede4bd7e78559156347df05c4c54480ca3775adac734f75334abe6be3c9237ce6c73d8b8f1e1a082c5c7e679eff6bd57a66f28017526f946cd3a58cf1ecb1b5d725ea77c45e834cd8fe09814b9376803a85a3038508e1372050176e7e4064b9c1cfcc9ba643864bbb819b2fe74439c72f51669f5e601ad3cd4ac3fc593f2b09b1c2a9ca6d57148c4f52e514630db428db6f5838a6187b0818e66e1485abc3bc73ee26f8a6d8a80b0f377907f9b590a70d4f22f40b4e381909a2101d7e11b833b368ae8ae06fc754fc56119f70d293a6d3e5f4e4b8aa044cdbd257dbe933c363ec2904d9be796b05fe3d0a0d9d69e587a48d3300b9541077acd87258d77d314edfe9bbb14e67d00f1f661b1a7d2572f7df3b897da276209890dea58fe8c2b00d34a10196e60f1a5dca4b71842c33c5bb819a6f4303616e718bf61070c1e8f12f353be087e28316f16339b11a60da66f551dc82e364e2cc32d773a710a19c6af33dbba5f3e0dbea1a5fea86d687e58de311969bc8f792f2ead60d5733ddb8f0bf69f6d1d3ab0328b408b9bc4ebeca25643c86c4af37000eec481811017bcd1ba1497bd770c833e99d597805e7461e2f6160a440d52e55364f5badb95fc9fe11
#TRUST-RSA-SHA256 55c40ef84aaccd9ed60b7077129d833aa9f67a965ddd723bf827435ee7828c90eb8f857afa056973a58d8c7040d78c23f096c37fcf811dd746315b1058fb64cd8342fcc1f8556acb2aa389c93479f99df6ff6e122e155cdcecd39c30b505738680929ca3857de39acf6001f75341490c28fddb0e764cd0b9a7706ee7f93c0f51d0e5d333c814c3c5cccc61509f0a2ef209b2d9a072b03890f793e640b1e467e9a5fffae77a885f5fa44afe5ba4cd13597b7135d16720ff2846e3e0cf1c8f5d832e55954c8a0c139c121990faf3d0c6c86af7552e04f8511e7b9051c3b655b00b58a8f60f51097ed77fa925781ab20a4cf7a38ff2a9dac2a479ea8cb0cb1210015e35d0e9b37101991882e17f478cde62e3320c716fec41c70e6c6c232eee0b5d88230a61e6a04ce850a881ca77cfb91c0bf7a0dd4fd8d03466129632a5e4cd8f5f4e50b29e1c1ca9fb5c3db3fb38751493cbf62baa50eb91d2b5df589466f8e70f8421e96b784b46db3271c8f80eac64864107e574eb897855f9e28df2aee3877693228fe0741197453b49e903642863cb1e701ddf75f58d758c14c2af3fb9d271bc07af21728d20c8ec8f9aec24f94d46be271324bab0f40250bef35d825fd6fe0afed5d78a2108fd38a23663a763e868c35fffae599f843ac27988f6bf6f1195fc51098afa499b15ad586d9d66400a74ae4a65c1b43f49f0399af377084e5b
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(177837);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/26");

  script_cve_id("CVE-2023-0026");
  script_xref(name:"JSA", value:"JSA71542");
  script_xref(name:"IAVA", value:"2023-A-0318");

  script_name(english:"Juniper Junos OS Vulnerability (JSA71542)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA71542
advisory. An Improper Input Validation vulnerability in the Routing Protocol Daemon (rpd) of Juniper Networks Junos OS 
and Junos OS Evolved allows an unauthenticated, network-based attacker to cause a Denial of Service (DoS). When a BGP 
update message is received over an established BGP session, and that message contains a specific, optional transitive 
attribute, this session will be torn down with an update message error. This issue cannot propagate beyond an affected 
system as the processing error occurs as soon as the update is received. This issue is exploitable remotely as the 
respective attribute can propagate through unaffected systems and intermediate AS (if any). Continuous receipt of a BGP 
update containing this attribute will create a sustained Denial of Service (DoS) condition. Some customers have 
experienced these BGP session flaps which prompted Juniper SIRT to release this advisory out of cycle before fixed 
releases are widely available as there is an effective workaround. 

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://supportportal.juniper.net/s/article/2023-06-Out-of-Cycle-Security-Bulletin-Junos-OS-and-Junos-OS-Evolved-A-BGP-session-will-flap-upon-receipt-of-a-specific-optional-transitive-attribute-CVE-2023-0026
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?be3e1b7c");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA71542");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-0026");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/06/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/30");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include('junos.inc');
include('junos_kb_cmd_func.inc');

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'15.1R1', 'fixed_ver':'20.4R3-S8', 'fixed_display':'20.4R3-S8'},
  {'min_ver':'21.1R1', 'fixed_ver':'21.2R3-S6', 'fixed_display':'21.2R3-S6'},
  {'min_ver':'21.3', 'fixed_ver':'21.3R3-S5', 'fixed_display':'21.3R3-S5'},
  {'min_ver':'21.4', 'fixed_ver':'21.4R3-S4', 'fixed_display':'21.4R3-S4'},
  {'min_ver':'22.1', 'fixed_ver':'22.1R3-S4', 'fixed_display':'22.1R3-S4'},
  {'min_ver':'22.2', 'fixed_ver':'22.2R3-S2', 'fixed_display':'22.2R3-S2'},
  {'min_ver':'22.3', 'fixed_ver':'22.3R2-S2', 'fixed_display':'22.3R2-S2'},
  {'min_ver':'22.3R3-EVO', 'fixed_ver':'22.3R3-S1-EVO'},
  {'min_ver':'22.4', 'fixed_ver':'22.4R2-S1', 'fixed_display':'22.4R2-S1, 22.4R3'},
  {'min_ver':'22.4R3-EVO', 'fixed_ver':'22.4R3-EVO'},
  {'min_ver':'23.1', 'fixed_ver':'23.1R1-S1', 'fixed_display':'23.1R1-S1, 23.1R2'},
  {'min_ver':'0.0-EVO', 'fixed_ver':'20.4R3-S8-EVO'},
  {'min_ver':'21.1R1-EVO', 'fixed_ver':'21.2R3-S6-EVO'},
  {'min_ver':'21.3-EVO', 'fixed_ver':'21.3R3-S5-EVO'},
  {'min_ver':'21.4-EVO', 'fixed_ver':'21.4R3-S4-EVO'},
  {'min_ver':'22.1-EVO', 'fixed_ver':'22.1R3-S4-EVO'},
  {'min_ver':'22.2-EVO', 'fixed_ver':'22.2R3-S2-EVO'},
  {'min_ver':'22.3-EVO', 'fixed_ver':'22.3R2-S2-EVO'},
  {'min_ver':'22.3R3-EVO', 'fixed_ver':'22.3R2-S2-EVO', 'fixed_display':'22.3R2-S2-EVO, 22.3R3-S1-EVO'},
  {'min_ver':'22.4-EVO', 'fixed_ver':'22.4R2-S1-EVO', 'fixed_display':'22.4R2-S1-EVO, 22.4R3-EVO'},
  {'min_ver':'22.4R3-EVO', 'fixed_ver':'22.4R3-EVO'},
  {'min_ver':'23.1-EVO', 'fixed_ver':'23.1R1-S1-EVO', 'fixed_display':'23.1R1-S1-EVO, 23.1R2-EVO'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);

override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  pattern = "^set protocols bgp bgp-error-tolerance*";
  if (junos_check_config(buf:buf, pattern:pattern))
    audit(AUDIT_HOST_NOT, "affected because the 'bgp-error-tolerance' feature is enabled");
  override = FALSE;
}
junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_HOLE);
