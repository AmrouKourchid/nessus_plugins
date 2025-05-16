#TRUSTED 4f536262abb2144ac3281cf65b58d6e46385a51dd9ad7b89a348970b962a555b43a5375dd41973a6ddefd9b9317682144f09b019f357fa4402c3dc8bb1ee5f2b511cc2c6178a80e26e11545a362593be7e085a3f75195eaf8ce0b4d9b62b11ae271d73cfc4a640bafae0102af30fc30be8f1950bba3b3a29b6fc06f743dffbd0d70f36026a517cc34d4f1a00729996d876878b0f6d7522fc846bdf2aa2af491a5c7471a9609212c20b508b863c24292804d6eb6b537d89299d070814ac4ee44e876b29ed2681eaf54812a06261a3dada0e2cb8f927a1daaa90d465bba4ea1d159c9554ad920d56f9815ace24f06bd9d26eb8da2d38e6876a2cda60ac93d3b9cd5879a3b10694fad14c933aa4632c46c9406b06f2471ec9ada6979f9b18d2cf7accc4076de9031e40fe7791d9434e7c0ff96d018403f6147ac78f92412719bb6b236b3d8cdfc820e75c5898bc6c85aeb13d12bcc78d5df5e21ba88d3338892d57fb0d5396b43bd658f4dd3db3ba7f0ff2e09e9587de7d82a7267aac1c8251c1c69754f0c78da5c22be836136b166116b3f990bfa7f239ea4e47023c382cf082617a6a1a627cff82c97fe69146f47ce2cbe3a441163ec63f2dbf90b43ced7e8e3d86b799b67e808987111b96b9127a4c72f51b603504f4ed567e1ef265effbd405f7d7a91bc458362305e5eb70c9c5be23df0f31f40fed08dfeb08810676ed0175
#TRUST-RSA-SHA256 158a3dfbea3fa916123e8886e9dab7caa67d644f13b32631c40bb9e745ebbaad5adb9f1afbf2758f895d920ba4dcc464b43ee7ece5c1eb14427dfd91528a28f11fdc295c7ea87d1bc1e4a5938c767ac79a5e535151ded3f7b5721d364f4bc0e32a6ce379115da1989e624d9713e77895a1e1ac5c2f755f62219607b074664697c1aa0b0df82ed448e9c1d161f14462a4af876f381e6d6e60230fef547b62bc77c6045bf575998557df5a40641c32ceab8a1308d7f62fa704565aed543fa42af309cd268560e6cd27ed088482fbe84eadd7f47d0a2533b1a313157044a37ed630ccaa3d3d1d633e7ba9dd7822fdfc94d2ec98005723f81ebedee97000ab9565190e259eabc8d222042aa6f17e5d4e49e7c67c9f39f119bb85b870aa82216aa28af059f59423bd4b116fb33716d295cd8fbb09c97576478b3397d5c5f280cd0ac9445a573fb72f52146082ea9c4af0b331b52b7ce392c10c1c14ccf3a4df5e89e1ecc04cff19ac81147bfb7d328078cbb08be2637d35b81090e1e985baf624c7e78e0678720a8c93a0c4dc89c8cd71acfcec7911c1629e36ce013419fa12305d566590180ea58cf55a45a4daad208306092651152dec286bfe11750203e1eddf04b82c2733b90a83920a9515610a342c1cd1ee2b1f615e9b0527bcbaea9fab2d6d1cfd16f1144131ef55bcb336e64b8bc0082ad18faabce6ba9f21199b7386930a
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(130767);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2016-6385");
  script_bugtraq_id(93203);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuy82367");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160928-smi");

  script_name(english:"Cisco IOS XE Software Smart Install Memory Leak (cisco-sa-20160928-smi)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a denial of service (DoS) vulnerability in
the Smart Install client feature due to incorrect handling of image list parameters. An unauthenticated, remote attacker
can exploit this, by sending crafted Smart Install packets to TCP port 4786, causing the Cisco switch to leak memory and
eventually reload, resulting in a DoS condition.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160928-smi
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b04d6eae");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuy82367");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s) CSCuy82367.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-6385");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/12");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list = make_list(
  '3.2.0SE',
  '3.2.1SE',
  '3.2.2SE',
  '3.2.3SE',
  '3.3.0SE',
  '3.3.1SE',
  '3.3.2SE',
  '3.3.3SE',
  '3.3.4SE',
  '3.3.5SE',
  '3.3.0XO',
  '3.3.1XO',
  '3.3.2XO',
  '3.5.0E',
  '3.5.1E',
  '3.5.2E',
  '3.5.3E',
  '3.6.0E',
  '3.6.1E',
  '3.6.0aE',
  '3.6.0bE',
  '3.6.2aE',
  '3.6.2E',
  '3.6.3E',
  '3.6.4E',
  '3.7.0E',
  '3.7.1E',
  '3.7.2E',
  '3.7.3E',
  '3.2.0JA',
  '3.8.0E',
  '3.8.1E',
  '3.8.2E',
  '3.18.3bSP'
);

workarounds = make_list(CISCO_WORKAROUNDS['smart_install_check']);

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCuy82367',
  'cmds'     , make_list('show vstack config')
);

cisco::check_and_report(
    product_info:product_info,
    workarounds:workarounds,
    reporting:reporting,
    vuln_versions:version_list,
    switch_only:TRUE
    );
