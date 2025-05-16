#TRUSTED 208a75d641666dca5882e0a9f3e3b472e4c0b882ee23d2f929817ef8ce4995ef2e5556109bfaf37c3314207a97f88f3dc955cb9b71f835a4ddf864646c4084e3e2666873badeec3724d6a46dcddd50822a77f842f06478c47d09a6dfa13f93c66914f410bd452fe6bc36d3df76f0425f529b32b2a7f12ae5d88a1367848f54a7bcb1a3fa93450058a486d538f3afac704ecc82867e26dffe6ff9942e945497a251633b4f8ac8321208986458582520bdd6e7c5b1d3d1133f38776dea6a1f0403630a0b57f5fb197aaec018f525ed4d090a792f46096eed6622fa556237480490155bd4baa90ce632cbf91a2a04717f89f1235bf31daaf2a65436b59f2060f6f6489eaf35484d96bd88f2998998f08d2461137a6f649cb6a6cbdc367e583441cd586cdf4339f84e7c18c0c41f5de2b53c6daa0b7896f4551d80856e545cd83f8c7c3a7338eb27c08ecfa3938257ec5e687cd92a9762306b87bc4bd425f2e6ad29f3d2d687faa5460a30d19765db7c3880b150d06d8ad7c752b969d6529dc9999c4fbf8c702cb6a290c8fec6cd05338d073798183ee96fff9fe80b1fbe3fad1d0cb55cc97d87dbb62b81d5bcde5ee119da16a82294722b5ec92a1f6cd71bac5e47fec695442e29f64537e29d8197c2275ee385e58a19a7438de618b76695ca24a865421425983b82fe1631f046549c5821d6be36eb4576c933d0503afac028aac0
#TRUST-RSA-SHA256 6ece4f96a02584b0627b5a3b9b16863475ec92bdd5eb3b2e22e457772e68e5060724b854d6444cd1042e118809552643daba66bb9c4fbc75c1785a4b4e2b68b2392bf141e336e33d0d12d1c5ae52119295900ef83050f7c4f1959af1aee8667a64712d84c3a81c452696bd54fc47d3875fe0dde38786cf6e1d46243432be7ceb5d3e4eba22dee9da50306d27a0dc1838e57a5862d0ed509c8e221c6c0d6ecf65ee9a3524d19aa2775edf0eae66880eb232d45b9aff9d88623aef86b9c84d66d550d20001a693b04ab57fb4e64d86a7bb2e331eff2b28e187ee4eaa63f0ac30dd6f81f5bdecae434221ec05e543ce6245a6dfe40abe9c98fd0298b791e9cf8fe10c02cb6327edf611859ae2b6935f85d48e40bdc477c09d7e28dd29f6686db6860d63f96a7b8eab0f86ac991a4ca2ec0cf23d14fa7d500d9644f395c688759dad0da7d99950e3e41399cc71f64300884789f4dcb8e227d9e3b2edf1ddbb1aed74d19ed059d6a3b17d081ad9d9824f13d18f2c355482f5c9cc18b9787a5c527435ec2258110b708bfd31ed4f1f56fcd24a5957936255b0505d887b5674466de30bc37405baa2bdaeefb1a2f017b71b9450a892d743db5fc40de8bb1b977281a6d6ea0e59cb2ca261a48b1fc2e1c602154458e3f8c8a016e38c44c39e15b37b1caca2daea000050099e8be1d038822a41486835f63af33d090f12ef0bbe2e50a8d3
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(169453);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/09/28");

  script_cve_id("CVE-2021-1624");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvx37176");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ratenat-pYVLA7wM");
  script_xref(name:"IAVA", value:"2021-A-0441-S");

  script_name(english:"Cisco IOS XE Software Rate Limiting Network Address Translation DoS (cisco-sa-ratenat-pYVLA7wM)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS-XE Software is affected by a vulnerability.

  - A vulnerability in the Rate Limiting Network Address Translation (NAT) feature of Cisco IOS XE Software
  could allow an unauthenticated, remote attacker to cause high CPU utilization in the Cisco QuantumFlow
  Processor of an affected device, resulting in a denial of service (DoS) condition. This vulnerability is due
  to mishandling of the rate limiting feature within the QuantumFlow Processor. An attacker could exploit this
  vulnerability by sending large amounts of traffic that would be subject to NAT and rate limiting through an
  affected device. A successful exploit could allow the attacker to cause the QuantumFlow Processor
  utilization to reach 100 percent on the affected device, resulting in a DoS condition. (CVE-2021-1624)

Please see the included Cisco BID and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ratenat-pYVLA7wM
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?82b10ce9");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74581");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvx37176");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvx37176");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1624");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/03");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl", "cisco_iosxe_check_vuln_cmds.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

var version_list=make_list(
  '3.7.0S',
  '3.7.0bS',
  '3.7.0xaS',
  '3.7.0xbS',
  '3.7.1S',
  '3.7.1aS',
  '3.7.2S',
  '3.7.2tS',
  '3.7.3S',
  '3.7.4S',
  '3.7.4aS',
  '3.7.5S',
  '3.7.6S',
  '3.7.7S',
  '3.7.8S',
  '3.8.0S',
  '3.8.1S',
  '3.8.2S',
  '3.9.0S',
  '3.9.0aS',
  '3.9.0xaS',
  '3.9.1S',
  '3.9.1aS',
  '3.9.2S',
  '3.10.0S',
  '3.10.1S',
  '3.10.1xbS',
  '3.10.1xcS',
  '3.10.2S',
  '3.10.2aS',
  '3.10.2tS',
  '3.10.3S',
  '3.10.4S',
  '3.10.5S',
  '3.10.6S',
  '3.10.7S',
  '3.10.8S',
  '3.10.8aS',
  '3.10.9S',
  '3.10.10S',
  '3.11.0S',
  '3.11.1S',
  '3.11.2S',
  '3.11.3S',
  '3.11.4S',
  '3.11.6E',
  '3.12.0S',
  '3.12.0aS',
  '3.12.1S',
  '3.12.2S',
  '3.12.3S',
  '3.12.4S',
  '3.13.0S',
  '3.13.0aS',
  '3.13.1S',
  '3.13.2S',
  '3.13.2aS',
  '3.13.3S',
  '3.13.4S',
  '3.13.5S',
  '3.13.5aS',
  '3.13.6S',
  '3.13.6aS',
  '3.13.6bS',
  '3.13.7S',
  '3.13.7aS',
  '3.13.8S',
  '3.13.9S',
  '3.13.10S',
  '3.14.0S',
  '3.14.1S',
  '3.14.2S',
  '3.14.3S',
  '3.14.4S',
  '3.15.0S',
  '3.15.1S',
  '3.15.1cS',
  '3.15.2S',
  '3.15.3S',
  '3.15.4S',
  '3.16.0S',
  '3.16.0aS',
  '3.16.0bS',
  '3.16.0cS',
  '3.16.1S',
  '3.16.1aS',
  '3.16.2S',
  '3.16.2aS',
  '3.16.2bS',
  '3.16.3S',
  '3.16.3aS',
  '3.16.4S',
  '3.16.4aS',
  '3.16.4bS',
  '3.16.4cS',
  '3.16.4dS',
  '3.16.4eS',
  '3.16.4gS',
  '3.16.5S',
  '3.16.5aS',
  '3.16.5bS',
  '3.16.6S',
  '3.16.6bS',
  '3.16.7S',
  '3.16.7aS',
  '3.16.7bS',
  '3.16.8S',
  '3.16.9S',
  '3.16.10S',
  '3.16.10aS',
  '3.16.10bS',
  '3.17.0S',
  '3.17.1S',
  '3.17.1aS',
  '3.17.2S',
  '3.17.3S',
  '3.17.4S',
  '3.18.0SP',
  '3.18.0S',
  '3.18.0aS',
  '3.18.1SP',
  '3.18.1S',
  '3.18.1aSP',
  '3.18.1bSP',
  '3.18.1cSP',
  '3.18.1gSP',
  '3.18.1hSP',
  '3.18.1iSP',
  '3.18.2SP',
  '3.18.2S',
  '3.18.2aSP',
  '3.18.3SP',
  '3.18.3S',
  '3.18.3aSP',
  '3.18.3bSP',
  '3.18.4SP',
  '3.18.4S',
  '3.18.5SP',
  '3.18.6SP',
  '3.18.7SP',
  '3.18.8SP',
  '3.18.8aSP',
  '3.18.9SP',
  '16.1.1',
  '16.1.2',
  '16.1.3',
  '16.2.1',
  '16.2.2',
  '16.3.1a',
  '16.3.1',
  '16.3.2',
  '16.3.3',
  '16.3.4',
  '16.3.5b',
  '16.3.5',
  '16.3.6',
  '16.3.7',
  '16.3.8',
  '16.3.9',
  '16.3.10',
  '16.3.11',
  '16.4.1',
  '16.4.2',
  '16.4.3',
  '16.5.1a',
  '16.5.1b',
  '16.5.1',
  '16.5.2',
  '16.5.3',
  '16.6.1',
  '16.6.2',
  '16.6.3',
  '16.6.4a',
  '16.6.4s',
  '16.6.4',
  '16.6.5a',
  '16.6.5b',
  '16.6.5',
  '16.6.6',
  '16.6.7a',
  '16.6.7',
  '16.6.8',
  '16.6.9',
  '16.7.1a',
  '16.7.1b',
  '16.7.1',
  '16.7.2',
  '16.7.3',
  '16.7.4',
  '16.8.1a',
  '16.8.1b',
  '16.8.1c',
  '16.8.1d',
  '16.8.1e',
  '16.8.1s',
  '16.8.1',
  '16.8.2',
  '16.8.3',
  '16.9.1a',
  '16.9.1b',
  '16.9.1c',
  '16.9.1d',
  '16.9.1s',
  '16.9.1',
  '16.9.2a',
  '16.9.2s',
  '16.9.2',
  '16.9.3a',
  '16.9.3h',
  '16.9.3s',
  '16.9.3',
  '16.9.4c',
  '16.9.4',
  '16.9.5f',
  '16.9.5',
  '16.9.6',
  '16.9.7',
  '16.10.1a',
  '16.10.1b',
  '16.10.1c',
  '16.10.1d',
  '16.10.1e',
  '16.10.1f',
  '16.10.1g',
  '16.10.1s',
  '16.10.1',
  '16.10.2',
  '16.10.3',
  '16.11.1a',
  '16.11.1b',
  '16.11.1c',
  '16.11.1s',
  '16.11.1',
  '16.11.2',
  '16.12.1a',
  '16.12.1c',
  '16.12.1s',
  '16.12.1t',
  '16.12.1w',
  '16.12.1x',
  '16.12.1y',
  '16.12.1z1',
  '16.12.1z2',
  '16.12.1z',
  '16.12.1',
  '16.12.2a',
  '16.12.2s',
  '16.12.2t',
  '16.12.2',
  '16.12.3a',
  '16.12.3s',
  '16.12.3',
  '16.12.4a',
  '16.12.4',
  '16.12.5a',
  '16.12.5b',
  '16.12.5',
  '17.1.1a',
  '17.1.1s',
  '17.1.1t',
  '17.1.1',
  '17.1.2',
  '17.1.3',
  '17.2.1a',
  '17.2.1r',
  '17.2.1v',
  '17.2.1',
  '17.2.2',
  '17.2.3',
  '17.3.1a',
  '17.3.1w',
  '17.3.1x',
  '17.3.1z',
  '17.3.1',
  '17.3.2a',
  '17.3.2',
  '17.3.3a',
  '17.3.3',
  '17.4.1a',
  '17.4.1b',
  '17.4.1c',
  '17.4.1',
  '17.5.1a',
  '17.5.1b',
  '17.5.1'
);

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = WORKAROUND_CONFIG['iosxe_max-entries_patched'];

var reporting = make_array(
  'port'      , product_info['port'],
  'severity'  , SECURITY_WARNING,
  'bug_id'    , 'CSCvx37176',
  'version'   , product_info['version'],
  'cmds'      , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
