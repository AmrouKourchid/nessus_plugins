#TRUSTED 836a3aad62aaf854b0ae7a1d746c2c5a7881d08d76c82ecb6898afab22ffc9b5c644ff84654c91d70e7174552224619b93e531fe8bd3b6a9b7bb0c88ff4199c8862db91e88c97fd1f47c9c7cca962b0c42fbf06580b9d1ecd72709be43e4023a8ed791299324d43d3a9ae810988b63273c5ac2369bd307317fb4e2d24809078cbbdda79ed9f651a2afbc938eb6544af0f75b8a800fd129556c5b10d81bb36f8764950de184a6c0fc86c25bd24b29d02b0e27b382d8a8a9dfbe7dc93b60fc9e4250388fd6404c6fdb22bed2020bd5234e09444eda9a5e9d9e63cc42bfc195940657236fc6d8611accb8486784bcaafa31362fef76630808ee389478159ec7217e64f9d752c3997e5869235b714063d8f4af7a9adeb23f48f3180d4a2f5001c12e2b97ea06e561ab6983764703a7dbfa48f21659c5b8d0ab316f8bc7638784ee6d1c436f47068461166e60fa704a35e93e8c438aacd6799d9dbdeadf43f32b42406e635a5ca58030f4259d668f8fea347802a4f5e9f4fa8d16d301311cb6b0f29035a0cf4549029ea1e6662da6863d0562652aa5b9741594edc7b161de3d5fba557161a3502302c03898f996f1be8506251e6e29b1c5faefdb7142c2cbe111bfdc3a715ff53c45b65e8aa8c44c60077a17b478e3913439ee1b602b7882c2cdbe6be9287c31c6ed1d3dac424e6c6903b6bc3ab6f1cb3f5979d8983b8c2926369092
#TRUST-RSA-SHA256 222a737aa252efb0f48aff752d6dab2e0ebfba572533b6a478c6e7e4e14d95b49de48c333eda7d7408b973caa9c9021b76df5807bb7e86187f02e2502de20c0f9a124dae444b5d2719d9e3dc5c595896ebf4ece19057234557d77b4f4df28bc4cae364b345800f91d20692e5ea7c746be32b5675d35e9c9242cc2db535f96dc33b9ddbbb0bb1d53c44517e10a903106e08206ffd7b11b47cc1eccdc14dd11c2f19abadf89a113f4f4179444276b1f2df52d86a2ce02de0bcb02939d3d7fe473e86609e09301a21c9ee907407af295eb626cbdf8c48da3218f71d80a255012e8776b759ffba33b1ea77b687b813f537ba467b3978bc044fcb30e3981777d5ac2663c6bb52f34db42dc6059ba78e3214f47803c05d568bc1db173b0b2b52eea3bcc94e2ae16b9e921d9f7b9be59a875df8a4b348be8528592a2a69af585328aeb1bfbe5918aeb0b14c22d373998d4d9e57ff48423e0ed84b363e143111214a01ecb747bc912c415d3030fce68c44637da7275ffda3894fe7387642287f425bacc7ea94addf350693118690d16a0bfe472571e4708cd3cf3081b2381ae4c8107969da5105c650afcac40b3229ec5005115963703542fd9fe9dcdeececb59c4236c8fbbca56a06a9394234c8ee786564a61cddbf80f5c858720f975391a1ca0a166f145ea31de56fc4340895e8ed730c2032dc38289bc922df6a71d591de4567f64f
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(129592);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2019-12663");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvo79239");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190925-ctspac-dos");
  script_xref(name:"IAVA", value:"2019-A-0352-S");

  script_name(english:"Cisco IOS XE Software TrustSec Protected Access Credential Provisioning DoS (cisco-sa-20190925-ctspac-dos)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a denial of service vulnerability. This is
due to improper validation of attributes in RADIUS messages. An attacker can exploit this vulnerability by a sending
malicious RADIUS message whil ethe device is in a specific state, causing the device to reload.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190925-ctspac-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?67bb03a0");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvo79239");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvo79239");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12663");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/07");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list=make_list(
  '16.10.1',
  '16.10.1a',
  '16.10.1b',
  '16.10.1c',
  '16.10.1d',
  '16.10.1e',
  '16.10.1f',
  '16.10.1s',
  '16.10.2',
  '16.11.1',
  '16.11.1a',
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
  '16.9.3s'
);

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['cts_pacs'];

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvo79239',
  'cmds'     , make_list('show cts pacs')
);

cisco::check_and_report(
  product_info:product_info, 
  workarounds:workarounds, 
  workaround_params:workaround_params, 
  reporting:reporting, 
  vuln_versions:version_list
);
