#TRUSTED 5d624e10c3dcfb4e56d477330de7a92f129e712a16ea5ba54a59b58dee4af94bdf84d5d6979f5d7048257349c2a2201da38b09674b47362e82c8296887d73c1317208e18005146f572f8d8817c733cd389f12ad755bcb0402cf85c7e31be6277cbb99e291391f1dfea1dbacdc5bd0cfedf86d917c68c03ba807028393dc577dc3139c0d90b8e20aedf3c7e5bd7508877ccb58f92473e0c0561fbc5c70cbf6014e81e79b9c8da5060e4251aada8581865985afe8bbfa20da5b99decc53be11c2ac9eafda2e5c5ca42b77e04bd8680757453a3b1e2e149ee201426354ddd7d2b669df48d2da683c1df8c7a9b2645bc07b1b18128e39a28950cb1c7f52e8802e8928cc3ae15db1657a6e97e2ea03cb59c724da90087fe15264b1a901ab01c59bec0512f12aa085ebbdf76dc389b7ae23af8fe9037f6ba4b567aa87521f009556129ca16a5621d4efe345eef1736fd72e1c6a0fa62027e1d748bfc38ad8ccc43d7e3d33ca67a35db310a4343753b2a2c3507d26e223a9b5380deb3652a44f274f8cfbb72f9834c0fab55785d0c7af14765b2414541311945776342c57a1333b32b191dc602f9bca18d0781d4c3f6053fb1f56332c15cffd6c9f641b8cc46fe5b82294a061ade38b095158af9c6b9847ee54ad1b625e198607f72a86644b0f8bdef8c5ba4fc17149c4e10f5a3a73a7247ccb788af5e99cb60de063aec469647cf5fba
#TRUST-RSA-SHA256 429eedbe07d587c1fd78d70a7285718a7ec3d7085a3e6e8c7639d8b3f05b5199d6af8d06021dff0c9df3a60c853de88eee8de97db14ee79c2161098932eee73c96f86fd9c3c203b67e513ef8000479aa7393b8c0fabf525524006899691450917398561b03e801836a6184f9b32060a10c58d23c3506b80f19b882df1b4a904b19f3f4cfce07f68d020a303a286276fb1a956f0b346f98c5031814f2379de8c5523f2d8e1852df6215472cc193410e4c1d28d30393eaa65e4d52447d7465ce4d801ccb3fa95a65ea8ad700ac134744b52d44466b6505f7a709753f9b72e9fb6ef1387a262a00b5c561d3ab5416a404ab6abd49bf9df856405ef4f570b2871d9c7fe031cb586343001e5522d3196cb3447d992cabaeac57bd3d063de23346c89d1c60128666d4dd5f07a2d9a1d40008592e9dad0da518dfdb612a4fc126f3240f974774b3e7cb9e50cddec26d61bed78f155a03ac6f3436ca8b0243abeb1b6691c6ba0ec874abeb78e3b24aca5f539a5aaf432b2f4d32e635b27fe486641f6316b316958b3789c0beadedb1af0f479c2874ab833e0a1bd2cec6a466bc603c1aa5f91fec62167dac2efb415a3b7392d6b1ae8204ed189d175c819db32dc344113da3da9b97fdaec4492d774961e26566b2f97214832d7aa3a6307ba39c6d1750bad1973757f4d036981e3678a413e459928a292f7c5cbf58829fbf649cb104db86
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(121643);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/20");

  script_cve_id("CVE-2019-0015");
  script_xref(name:"JSA", value:"JSA10915");

  script_name(english:"Junos OS: Deleted dynamic VPN users are allowed to establish VPN connections until reboot (JSA10915)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos device is affected by a vulnerability that allows deleted 
dynamic VPN users to establish dynamic VPN connections until the 
device is rebooted.");
  # https://supportportal.juniper.net/s/article/2019-01-Security-Bulletin-Junos-OS-SRX-Series-Deleted-dynamic-VPN-users-are-allowed-to-establish-VPN-connections-until-reboot-CVE-2019-0015
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5e522c77");
  # https://supportportal.juniper.net/s/article/2019-01-Security-Bulletin-Junos-OS-SRX-Series-Deleted-dynamic-VPN-users-are-allowed-to-establish-VPN-connections-until-reboot-CVE-2019-0015
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5e522c77");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA10915");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0015");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/07");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
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
  {'min_ver':'12.3X48', 'fixed_ver':'12.3X48-D75', 'model':'^SRX'},
  {'min_ver':'15.1X49', 'fixed_ver':'15.1X49-D150', 'model':'^SRX'},
  {'min_ver':'17.3', 'fixed_ver':'17.3R3', 'model':'^SRX'},
  {'min_ver':'17.4', 'fixed_ver':'17.4R2', 'model':'^SRX'},
  {'min_ver':'18.1', 'fixed_ver':'18.1R3', 'model':'^SRX'},
  {'min_ver':'18.2', 'fixed_ver':'18.2R2', 'model':'^SRX'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
