#TRUSTED 2a3de977f9d562241a09ce6bb4c11853bb0f62cb1008d4c8cbed61c7c63349a8e39ebc590435a427bf50c6f3195026f24e224ec4bb7208da22ec212a221fb71be4530c889905367a7888aa198c16fcc2379e6915daec9068d1b739cef6899021281cdacb82694512aeabfa050908276134e3c47d15ab0accc64cb1152d57606b7b4d21e59525d61c988e29d5a9df5ed4aa27316d62e1cd5529b285bb0765b97f46082a477fa9f8cf66d4c5e799b738d61f6220560ad12ee3808158c8a6c73fd5a75f94d873e4455ee2782a16106825310ea30d297310a91e754be6caeef8d9f452db5a7ba16b8d40795569ed0a52103ac2898ce29040ced99345421f5f8264d54347cd2016d872bca5244f9c0396e9ba62edb7560174357673ef66a3cfa0ec033dcaee21dada322652c0189520da335d14aa60d1c02ea9bea98e9f9d83d4907fa0b913cf214c13dff98dfe985a335f464bb1d8cd2d9fe07d460381f66435bc5dab36b63337bbaddefa8525d489e37c2157dc475aff2051336a2dff2bdc7aa4cd677b18f287470f52795a98a61d8374f1897b4a349e3e954e1a5ff1f182a646c547fd7b4bd89a9096f3b7a7dca3df04f34da10d12d7888f09c800ec284e961dd741a2aa9624cfac0759a0cf32fb25291b97a4e7621e1713f6df8ec64793033e4e8a7acbaf05cc5c2387b0f9518386f77b62fb657b17f6dc328b327e8911cbb116
#TRUST-RSA-SHA256 97fcd5333456827cb53d5984aea6f4343231d48fabdc7dd83e72593b60dfcbf559a8a49ca7573dbf5cd9f9b175697620bf4601a043584bf5b1da7129b416660bf420ce0ec2407f6f2cf48a535d95db17e7a3ac51af63097876985f1cde4f62ea718912d6079fffa020a4048754d09b6f6f16132038b7b16987c888cf06a4460522f12cb37646f4debf269b69e721e2d7b7f41951399dc915e2372a8f6429d849843d2d2d91562d11cfaad23b9e2721459c9ad5ed5361ecfda0184e1f247304da3845749a02905aeac81c3c637401881a9b7e37bbbd9e29a7124b27e6e95a73b1c7fb3f0dd1a0c84eaf8ec5039cc8151423802a27ab474a938b884943e0aefac6bb15806ca6bd3d35938fd9af8972f1910fb07738e35c10ff24c42e8b9bc99c096bb2b1d256bae784de3021e063983021acb41f8c77ca8555ef60c50d31f41f6747ca4e983c8d87bfc21835c1d84a7bb9b869ae7e73a972c195123bf4035ab6ee2ff88f3ba7a197252e554ca52bb140d169f60d3eb5ef259f8e863a9ece3fa77fcdfa72d04d48ea6bfb68389e4cc2b369f5e323cd28ef87912438b5b0ec6e4a8f16f52fd1f3e41e6c15e5751d4d73448c6718ef05fdb3522c1da8b6045ca534c2151533b57f13860de57085425dd8f5a63d75f75110a1bcea8e6bb702f1eaabc5325404134be6c1ac863ac05f2e0658e019e27dd637762bb9b14c911aeb417fc7
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(130467);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/20");

  script_cve_id("CVE-2019-0075");
  script_xref(name:"JSA", value:"JSA10976");
  script_xref(name:"IAVA", value:"2019-A-0388");

  script_name(english:"Junos OS: srxpfe PIM DoS (JSA10976)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper Junos device is affected by a denial of service (DoS)
vulnerability in the srxpfe process on Protocol Independent Multicast (PIM) enabled SRX series devices. An
unauthenticated, remote attacker can exploit this issue, by repeatedly sending crafted PIM messages, to crash the
srxfpe process and cause an FPC reboot, leading to an extended denial of service condition and causing the system to
stop responding.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://supportportal.juniper.net/s/article/2019-10-Security-Bulletin-Junos-OS-SRX-Series-Denial-of-Service-vulnerability-in-srxpfe-related-to-PIM-CVE-2019-0075
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ab65976d");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA10976");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0075");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/04");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include('junos.inc');

var model = get_kb_item_or_exit('Host/Juniper/model');
if (model !~ "^SRX")
{
  audit(AUDIT_DEVICE_NOT_VULN, model);
}

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'12.3X48', 'fixed_ver':'12.3X48-D80', 'model':'^SRX'},
  {'min_ver':'15.1X49', 'fixed_ver':'15.1X49-D160', 'model':'^SRX'},
  {'min_ver':'17.3', 'fixed_ver':'17.3R3-S7', 'model':'^SRX'},
  {'min_ver':'17.4', 'fixed_ver':'17.4R2-S8', 'model':'^SRX', 'fixed_display':'17.4R2-S8, 17.4R3'},
  {'min_ver':'18.1', 'fixed_ver':'18.1R3-S8', 'model':'^SRX'},
  {'min_ver':'18.2', 'fixed_ver':'18.2R2', 'model':'^SRX'},
  {'min_ver':'18.3', 'fixed_ver':'18.3R2', 'model':'^SRX'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
