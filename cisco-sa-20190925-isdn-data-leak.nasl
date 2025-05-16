#TRUSTED 8f0328037158b607365d89f4225dc8668b3cb7e9ef0c9cbabce2574e21e3091819859c87c30586e7d0e9a8f492dbc65e345d068000afea9979ea7645a72a765602dffb59abf4a0c3b3d25b78ac973ffc763e6d1a489768993ce6d1f701352b351a75169b429cf3e831b4ac2f3abcc54cb5045a8d348446da61ee7ee42bfb256d8666aa0c3cf64c47be590488cb2b895fa0c55f98b46903d16adba9b59312ed05f5d8f57c60490c1aed7d3215787ba4d0fe36c16bc4b01af18a822716d5b5043a7e684af4113a6c3fc330c87b5d7a998ee92067d878c2f19a435aeb9c56ddccd6a1d8fb0eb48d51d5eb179ec91cbce327f37a60c4d3abb30639c5786db0d9d834af5e3c19ba6f477a39f215940a826974ac90809055067deda1c3b88c001351a0291c208eac4c3a3685ac4696059625e16551da162f5121d2eda355d8a900cc5a3c56082a5c3db634c279c01b294a9a47d83d2299094b319e9dfcf5dddff328cc77a4ebc8ca6ccfc63c4db1f65af6aa386180de9b64c28a62d4f2d30c09b1e0e8060b4844d0aa66a2c15b0146912e2a009e9de7709c118749c787eb8061a9c37e86c7759a1d935acad00fb488b71879e76a74464b0f0f10c99ced668a12a86c6f1ad5870bae610fa4ca09969290f13ad20acbb6de78a39cdac80f491689fb2913a9cbdf494a4d605d22ad286267a4dc30785a51aeb1a5bdee6240dae28b269853
#TRUST-RSA-SHA256 0b739fa79d77daa84218408f378773c4cdcced16a4a71a55e6af1967a9ceb20bba6f2ea0a3ea4de5cccd95718f7022fefd5398c9f761e45f30fa37281a23accdc59fcd41667d17d614f089615e13cf82f225fafad0972450d5a9163e7a34ac3b85c83b4e1befffa74058c84c51dcf04826bbdb23157c2333ef429865271f3ac72abf9c0c6f144a0636ade84bb9980571093fac7f328b65555972d7942bfd62ebdbfbf54104cab77e575e6c9a07f661d1bb0d0dc88824770be759f8a8bdadf2b02759ea706160a916573c02c426004ce6ce55d5b80428da5d7dfb42d0fa049fd46da506066e07753a704b639514b21e317fc1345a53bb2457e84b62e80113d90d8a4de11f7d465c30eda050777a1c67f0ae439635260dad322922e0dd029a433c5556a51c723f3a49aa512933e2c61d831905caf3631d5845830152a69359cc609d3681c3dc2fb62c9aa7dbbfc0ee7f712e5c50af304ebdb326f544d90efa4947e0eb2f2162ab458dd1ea1eaef44d3244b58ac888e14cb5057cd0d07999919e90810669d9f23cfec433db85431a2a7f347f72cf60d3351e90ba880c357463d1e362d681e74ff95559d1e98093f7c553d276bfe651c5c7c58d8e24670857defd73f32f8fd12aa63920acd73adb05aced83766cca23835a4c4b01f6d099e22d22d08d33466df4ddf5509858c0e0ca81bb180365a880856203428f7bbd9e070b3395
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(129530);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2019-12664");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvk42668");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190925-isdn-data-leak");
  script_xref(name:"IAVA", value:"2019-A-0352-S");

  script_name(english:"Cisco IOS XE Software ISDN Data Leak Vulnerability");
  script_summary(english:"Checks the version of Cisco IOS XE Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a data leak vulnerability.
Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190925-isdn-data-leak
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?32058d0a");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvk42668");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvk42668");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12664");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(200);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/03");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Settings/ParanoidReport");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list=make_list(
  '3.6.5bE',
  '3.4.6SG',
  '3.4.5SG',
  '3.2.9SG',
  '3.2.11aSG',
  '3.2.0JA',
  '3.18.4SP',
  '3.18.4S',
  '3.18.3bSP',
  '3.18.3aSP',
  '3.18.3SP',
  '3.14.0S',
  '3.13.9S',
  '3.13.1S',
  '16.9.3h',
  '16.9.1s',
  '16.9.1d',
  '16.9.1c',
  '16.9.1b',
  '16.9.1a',
  '16.9.1',
  '16.8.3',
  '16.8.2',
  '16.8.1s',
  '16.8.1e',
  '16.8.1d',
  '16.8.1c',
  '16.8.1b',
  '16.8.1a',
  '16.8.1',
  '16.7.4',
  '16.7.3',
  '16.7.2',
  '16.7.1b',
  '16.7.1a',
  '16.7.1',
  '16.6.4s',
  '16.6.4a',
  '16.6.4',
  '16.6.3',
  '16.6.2',
  '16.6.1'
);

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();


reporting = make_array(
'port'     , product_info['port'], 
'severity' , SECURITY_WARNING,
'version'  , product_info['version'],
'bug_id'   , 'CSCvk42668'
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
