#TRUSTED 2be4303926f7746dd42baefddaeafc82bc5a9622b0d220006d08f4f0c86058689030f4f54b0c28c8e92eeeb2aa0100529e1a7ea83909e0ff86f8c4e3f3e314fe1ff3759bbeaba376f124424c4cb81b3b78208ddf93c1a08588c071d314aed0a71a113da0793a20676ebf4a168307be88065479da9e4eb263a9754b4cc665095e89c03bdbfd6aaaf7c8a02c8e9adc4d05829fd6bc4348fad490c58d88c44b4a907983fa0d84d2ac5d36cfc3df416b0a263489927bc310b7ca83f525331cf9fac17a9e6dda2f21355ed02bc34b33e2d45aa264bae1a9b81d47790fe8ac2112982efcdd660f62d18274500c461ff1bbf4f5b15edef4f59863b98b974e8ca8ffffb0135c70aa03ea2687e7658d8deec7f307855da113495cde4377612e8042c645e894ac51b11f14c79b38e1a838c978fdcf05494dc9f384df4b0960405b9b3092e736327f41e7fedb8ef61d6779a68d175d7b2069a681f71fdbe2f6ea1e1a466f690030ba1c223fc2ce23076951a66e77db6e143bb65e2329c64711e5ce55acde7bb69a49756835ddfcaf6fe7689cd08b083f113403bee4681d16fa2fa8bce9f1e00a79a44636258d1df33e525a2e21c00349dba2c2669260358f86802adca30bf63eebd67f68710c6ca2112e328c9e73e71f8fd73e3f0e5d28a18ab1383aa124f2159d7c7814390a41df5a7eb8bdcec6f03011a0b2c8670df6fafb736181c1de70
#TRUST-RSA-SHA256 7c3a1c6704e9f6db64f6653eb285d7d245cb67d7edd0867b6f95827246fd29daa022902dbe8960de499b8744f8c1b697474d7e450c73e244b7ca0ea8c6b83924f5ae68d41ea324d7428dba03d9608cd87a9ec4c9b3289382d1acea9a5553ae209a368cc99801f64ef6c168c48b5f418404b3ffe2b708ccedf41b99fb8d15f4c5bdac84ca29a5b5fa06ebc3b46fbdc532cd1095dc715ea1d5e3dfddddca950fad3e1ea4137ec90b594aebb7dbb140f7eec0d122808f1e4b7d104c812b6fe13f7c55325289a22c8dfc54503845a09e0dd75e1074570dc8cf111a439a563c517c96851b7e9915e577ec8eb73f7a7b7bdb6c810a4a087734aff15edec1ad40f2e2a815c9013e31d61f16d1483052c9389aa51ea799f74bd910b502fee00d4d73179df9099abb03dc4a952ded05e745579f1d75007a94020b03daae59553e6b71febc73184d719c3f3926be5c7b23974f265d61c6e115941e79c6ab06eff1d2cfa03013a1aaa417ac2e6470b2968406729ee2dd22622c79fa1ad03ccd7b86033f6ec9c59518c1177a6803e2d88185a1a7daee1ecc849147a5d6ac7ae3d7140b414ebc971e0decccf1b0f22e775843faec07e971a0ff6fd9295a143b76067f3afcf233f81a564669177815f0591a9bb1c8b2fbbbe78ca236ecbced2a8a4ff77fbe583f49af28f6234beb85875920cdf9b0a3c1156e85258b07e212382f333e958dc86e
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(213466);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/02");

  script_cve_id("CVE-2024-20480");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwk36431");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ios-xe-sda-edge-dos-MBcbG9k");
  script_xref(name:"IAVA", value:"2024-A-0592");

  script_name(english:"Cisco IOS XE Software SD Access Fabric Edge Node DoS (cisco-sa-ios-xe-sda-edge-dos-MBcbG9k)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS-XE Software is affected by a vulnerability.

  - A vulnerability in the DHCP Snooping feature of Cisco IOS XE Software on Software-Defined Access (SD-
    Access) fabric edge nodes could allow an unauthenticated, remote attacker to cause high CPU utilization on
    an affected device, resulting in a denial of service (DoS) condition that requires a manual reload to
    recover. This vulnerability is due to improper handling of IPv4 DHCP packets. An attacker could exploit
    this vulnerability by sending certain IPv4 DHCP packets to an affected device. A successful exploit could
    allow the attacker to cause the device to exhaust CPU resources and stop processing traffic, resulting in
    a DoS condition that requires a manual reload to recover. (CVE-2024-20480)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ios-xe-sda-edge-dos-MBcbG9k
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2710d954");
  # https://sec.cloudapps.cisco.com/security/center/viewErp.x?alertId=ERP-75169
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e0341eea");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwk36431");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwk36431");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20480");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(783);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/01/02");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Settings/ParanoidReport");

  exit(0);
}
include('cisco_workarounds.inc');
include('ccf.inc');

if (report_paranoia < 2)
  audit(AUDIT_PARANOID);
  var extra = 'Nessus was unable to check if device is configured as an SD-Access fabric edge device by Cisco Catalyst Center.';

var product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

var version_list=make_list(
  '16.1.1',
  '16.1.2',
  '16.1.3',
  '16.2.1',
  '16.2.2',
  '16.3.1',
  '16.3.1a',
  '16.3.2',
  '16.3.3',
  '16.3.4',
  '16.3.5',
  '16.3.5b',
  '16.3.6',
  '16.3.7',
  '16.3.8',
  '16.3.9',
  '16.3.10',
  '16.3.11',
  '16.4.1',
  '16.4.2',
  '16.4.3',
  '16.5.1',
  '16.5.1a',
  '16.5.1b',
  '16.5.2',
  '16.5.3',
  '16.6.1',
  '16.6.2',
  '16.6.3',
  '16.6.4',
  '16.6.4a',
  '16.6.4s',
  '16.6.5',
  '16.6.5a',
  '16.6.5b',
  '16.6.6',
  '16.6.7',
  '16.6.7a',
  '16.6.8',
  '16.6.9',
  '16.6.10',
  '16.7.1',
  '16.7.1a',
  '16.7.1b',
  '16.7.2',
  '16.7.3',
  '16.7.4',
  '16.8.1',
  '16.8.1a',
  '16.8.1b',
  '16.8.1c',
  '16.8.1d',
  '16.8.1e',
  '16.8.1s',
  '16.8.2',
  '16.8.3',
  '16.9.1',
  '16.9.1a',
  '16.9.1b',
  '16.9.1c',
  '16.9.1d',
  '16.9.1s',
  '16.9.2',
  '16.9.2a',
  '16.9.2s',
  '16.9.3',
  '16.9.3a',
  '16.9.3h',
  '16.9.3s',
  '16.9.4',
  '16.9.4c',
  '16.9.5',
  '16.9.5f',
  '16.9.6',
  '16.9.7',
  '16.9.8',
  '16.9.8a',
  '16.9.8b',
  '16.10.1',
  '16.10.1a',
  '16.10.1b',
  '16.10.1c',
  '16.10.1d',
  '16.10.1e',
  '16.10.1f',
  '16.10.1g',
  '16.10.1s',
  '16.10.2',
  '16.10.3',
  '16.11.1',
  '16.11.1a',
  '16.11.1b',
  '16.11.1c',
  '16.11.1s',
  '16.11.2',
  '16.12.1',
  '16.12.1a',
  '16.12.1c',
  '16.12.1s',
  '16.12.1t',
  '16.12.1w',
  '16.12.1x',
  '16.12.1y',
  '16.12.1z',
  '16.12.1z1',
  '16.12.1z2',
  '16.12.2',
  '16.12.2a',
  '16.12.2s',
  '16.12.2t',
  '16.12.3',
  '16.12.3a',
  '16.12.3s',
  '16.12.4',
  '16.12.4a',
  '16.12.5',
  '16.12.5a',
  '16.12.5b',
  '16.12.6',
  '16.12.6a',
  '16.12.7',
  '16.12.8',
  '16.12.9',
  '16.12.10',
  '16.12.10a',
  '16.12.11',
  '17.1.1',
  '17.1.1a',
  '17.1.1s',
  '17.1.1t',
  '17.1.2',
  '17.1.3',
  '17.2.1',
  '17.2.1a',
  '17.2.1r',
  '17.2.1v',
  '17.2.2',
  '17.2.3',
  '17.3.1',
  '17.3.1a',
  '17.3.1w',
  '17.3.1x',
  '17.3.1z',
  '17.3.2',
  '17.3.2a',
  '17.3.3',
  '17.3.3a',
  '17.3.4',
  '17.3.4a',
  '17.3.4b',
  '17.3.4c',
  '17.3.5',
  '17.3.5a',
  '17.3.5b',
  '17.3.6',
  '17.3.7',
  '17.3.8',
  '17.3.8a',
  '17.4.1',
  '17.4.1a',
  '17.4.1b',
  '17.4.1c',
  '17.4.2',
  '17.4.2a',
  '17.5.1',
  '17.5.1a',
  '17.5.1b',
  '17.5.1c',
  '17.6.1',
  '17.6.1a',
  '17.6.1w',
  '17.6.1x',
  '17.6.1y',
  '17.6.1z',
  '17.6.1z1',
  '17.6.2',
  '17.6.3',
  '17.6.3a',
  '17.6.4',
  '17.6.5',
  '17.6.5a',
  '17.6.6',
  '17.6.6a',
  '17.6.7',
  '17.7.1',
  '17.7.1a',
  '17.7.1b',
  '17.7.2',
  '17.8.1',
  '17.8.1a',
  '17.9.1',
  '17.9.1a',
  '17.9.1w',
  '17.9.1x',
  '17.9.1x1',
  '17.9.1y',
  '17.9.1y1',
  '17.9.2',
  '17.9.2a',
  '17.9.3',
  '17.9.3a',
  '17.9.4',
  '17.9.4a',
  '17.9.5',
  '17.9.5a',
  '17.9.5b',
  '17.9.5c',
  '17.9.5d',
  '17.10.1',
  '17.10.1a',
  '17.10.1b',
  '17.11.1',
  '17.11.1a',
  '17.11.99SW',
  '17.12.1',
  '17.12.1a',
  '17.12.1w',
  '17.12.1x',
  '17.12.1y',
  '17.12.1z2',
  '17.12.2',
  '17.12.2a',
  '17.12.3',
  '17.12.3a',
  '17.13.1',
  '17.13.1a',
  '17.14.1',
  '17.14.1a'
);

var extra;
var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = make_list(WORKAROUND_CONFIG['dhcp_snooping']);

var reporting = make_array(
  'port'    , product_info['port'],
  'severity', SECURITY_HOLE,
  'version' , product_info['version'],
  'bug_id'  , 'CSCwk36431',
  'extra'   , extra
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  reporting:reporting,
  vuln_versions:version_list
);
