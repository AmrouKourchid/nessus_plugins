#TRUSTED a2c6b27becf98fa59f77756a08b5f0f83b35009e93d6d45e695d1035b143456aa5acdd5a9136f60521069d493df3f68e57945fe27a97b4ac4057c0b4394d8568db9da33aece53824a0db965361aa1bb5feaf0ee537cc87348491e53b2afc07814b8ae420b8d8c1b2e55f7a9ac819858ab40ca7567b0d8a40b08255a69bcd0a1ed57aa82ea584e717d0e04c837fc69d33b6cab7e3339d21b7da03bee8f9298f73b1ee8fa34b4bf6700ed5ca06ab5745cb2328830493f50849924b16e77bac58b43c10b0e941326c75ddbf9985f8e6a7cfe3dfd80300a1a80bc76a2e7e5eb630d85490bda73d1b8815f9de9bdedf8f42799412dea04125dc73d5c648cffc6b9cec5d40c9c6537258bef0e5fafbec1dae868cb6edf3b2436a81952c9eef21ec6a95c18433f042fd3307cf9383d1acd3c91ebb80e1db8201cfcf2a5bb9bc727e607d7f6a0c858916b6ee47ad5209d070eff0ac8f9ca142e42c1ddf936af37f86ba2cb1df53891fc7cc8f743e136b07e2a3c0f2abecf4406aa32842651c58c1e35d0f4bda7929b71b298f9939a8cc8b3f873b9432ac36e0f24c3546840f781ff75c4b56d7d7d470a8e89b9b840f0b75f2f3d9dca73b5d54e92e2012b4088ca47090472ce7b396baeffed095e4fafba1b248778398ab2e89c06adba21da4280feb1c581706ea25afa9f4e2c81231f0637371033cdb989c429b2028d8d18db891b39c26
#TRUST-RSA-SHA256 37bc83753fad06954d77876592b119b562836bec2733258184b5b6166c801c31b7d244d50f9bed05f78b30834c4e20f1e6e8f2bf7a127c5a19ce4585397ce8e742773d4552c26dfecca09acebb8b4098a58f7e88b9faafa90a07d20d89aef558edc99431b0f9164c41a80f129dceb24b08e56ebc0483e6abb191e030ecfeb10150627db101f01f81e182f55656417a2ffba8eeae1965543882f15458531c207c584da478b6b802dfb365241de0577c5068556bf8ead33b3819b21aad64b7c40a615964f5a92c3919e21fc92369628a8a41bfaad4496103507f220d1453a841df6eacfd79c1dd093c1e1025582d84ed57c2452ac07c02469e99b20403bd9ffd37f8a70a9758a956a063bdd7c3f9b481ab55de664a161ed282bc0d3e952f229f01a30149d94169adfc0afcacec694f1b39ae2821a2fd0874eb4e384fb5e82acac5963c1800caffb0aaad772387506ce0b2c491ff881be85d535e64b1f1f5158e988fbcdfb640c3fced91c179bfab8e8396509fee011421227be79e276a8b05e4dd81969abf1cd7ab34c085d6271fe65d90bc7784804c35ed7425f8fc071e69780c4796f55d191eb2ec284f0bf29502730befcd4da06d796a2467e870bd003788c04b8ef3a4f875c1730b0e28851b86150b124b29aae000eacd029532651c1a50d82117ea6ac706cd5402750ab4cfee7d4978651b8eaef2590feed2e62949f42c8c
#
# (C) Tenable Network Security, Inc.
#

#%NASL_MIN_LEVEL 70300

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151634);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/12/08");

  script_cve_id("CVE-2021-0291");
  script_xref(name:"JSA", value:"JSA11193");
  script_xref(name:"IAVA", value:"2021-A-0324-S");

  script_name(english:"Juniper Junos OS Vulnerability (JSA11193)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA11193
advisory.

  - An Exposure of System Data vulnerability in Juniper Networks Junos OS and Junos OS Evolved, where a
    sensitive system-level resource is not being sufficiently protected, allows a network-based
    unauthenticated attacker to send specific traffic which partially reaches this resource. A high rate of
    specific traffic may lead to a partial Denial of Service (DoS) as the CPU utilization of the RE is
    significantly increased. (CVE-2021-0291)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-0291");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11193");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11193");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-0291");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/14");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include('junos.inc');
include('junos_kb_cmd_func.inc');

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'15.1', 'fixed_ver':'15.1R7-S9'},
  {'min_ver':'17.3', 'fixed_ver':'17.3R3-S12'},
  {'min_ver':'17.4', 'fixed_ver':'17.4R2-S13'},
  {'min_ver':'18.3', 'fixed_ver':'18.3R3-S5'},
  {'min_ver':'18.4', 'fixed_ver':'18.4R2-S8'},
  {'min_ver':'19.1', 'fixed_ver':'19.1R3-S5'},
  {'min_ver':'19.2', 'fixed_ver':'19.2R3-S2'},
  {'min_ver':'19.3', 'fixed_ver':'19.3R2-S6'},
  {'min_ver':'19.4', 'fixed_ver':'19.4R1-S4'},
  {'min_ver':'20.1', 'fixed_ver':'20.1R2'},
  {'min_ver':'20.2', 'fixed_ver':'20.2R2'},
  {'min_ver':'20.3', 'fixed_ver':'20.3R2'}
];

var override = TRUE;
var buf = junos_command_kb_item(cmd:'show configuration | display set');
if (buf)
  {
    override = FALSE;
    var pattern = "^\s*set snmp subagent tcp";

    if (!junos_check_config(buf:buf, pattern:pattern))
      audit(AUDIT_HOST_NOT, 'using a vulnerable configuration');
  }

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (!isnull(fix))
{
  junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);
}
