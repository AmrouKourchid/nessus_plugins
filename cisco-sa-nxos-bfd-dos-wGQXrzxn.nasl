#TRUSTED 490db335db2a5782af3ad9cfd6fed4d97de54857b75cfe3098449d39ac4278c5762bc1e99961ac6769dce3bedc2e4597def862d7988c6368a60f2357a9577950fc35f28b48cb2a3b9728488d05b582c0b7cb995d6cbfc0866b3662c95b3e1275d86bf0e0d3cce2ee6d497d27d89fb9ca07b4971bb5fa0ff4f1517012aaabd46f8c1139d5ed201e66e8618d8c5bec20013bcb3bc48077e15f3a68d17ca1f14d114f5b4e2cd7b632b59dbc49300858ac019627fa00d41e6b2d4cba0924a071e31857a86aba9e240461ca4cd4e89ffdd4721175486679004e1dc38e859e99d64e7a5608bb733799326b1bdc1aac50f7c2166d49f7ac3d606f35ce1ed83258a510e0ae277c22ced83fe9052b01aacfd756c06d9f57c6ff509a8937eacd2dfcf67542435159af4cdaa2575f742dbf9485ed4364ca466420631b8bfe13c42c5e567313c1f9f6407c6104d5bb431a44704c29041e16f4b343ea5bc5ad6af63e37efe786211f186fed4cda4be7c1ac986da64176de7d7e96d041bbe0a1fb95a4b46782d9a624f63d6b6e72622d5aae242a03a1b0581f7860f2083f6d0fe2cc8a1531b83a60b43aa193bf5da5d9d43cf304fb3c68345828e76b8072b315335ed2501bf0729ff9c42e840ccbf2072df5e7c4978d45d5f0a9afed4bc33e8683aa2873c6fe96f5b6fb77be93c32907b63a804eba017618f38818f164e5036176dd27e3ee5e0a
#TRUST-RSA-SHA256 795a9e60a025a0abeb8f3d46a7974faa4d1ea43cea2aa68a3869179104e9945cad3c36db85be9c137ea9aeec6a2d4bad37413d496b62e0b90bd736d66ccc2b5eda58391aae4f8c412c80fb1785fd0d1fc9f03f75adb4065e734fe9cdfd7f52bf168d417f52dc463b305813f11f0ebc0e29bd6cd5d5fa675c1f9b60f0bc7a2f628ba3d299624049e19c1147553aa2442e2ab3080b0b5ae958f4143334430cdba77b1aaeb89836ff88410c51f98389a403d30a1eeb2fcd184b90df5326903f906f8217c970fe1ddff899f86f0ae9b6b194f03f4b817237f5c776a138d4f39bf1ffd4ad9eba4c9ff93cc905e01c1170bc9ac9c32107c8ff2d1b7a59d5707925ed0e26044478577c125912c0fbf912d0fc79689a7ad1bc7d4916539b85e1ef83046227b27f34ddf0cf95db00f84cf6de2563c80b4aaa2c301bd032083b03ccf3f22a12dc1c3b39e329eac372c709386202aa22657df278da4cb743b8ddb6632224ee09fddc5057821735f98d130fca19b29faf880d22e8ab58e72e5fede2a4a8444019ac92d178628673f4b8cf0f317a8596111d4b94f5fcefc229bfcee2a8f15cd7a9e142abf39d39c10e9e250b7d88d6b9da30474fb32edabbf1d7fc4a21387d2c17e13c1f1f68a5e0f3f06e07a2a1f2e1f7ca0a95af676939c700c746b4e1be098449e0caec66a2ba76f12e4925311d46f226a6a04d420182b1ead0d6431a23a7
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158887);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/13");

  script_cve_id("CVE-2022-20623");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvx75912");
  script_xref(name:"CISCO-SA", value:"cisco-sa-nxos-bfd-dos-wGQXrzxn");
  script_xref(name:"IAVA", value:"2022-A-0095");

  script_name(english:"Cisco Nexus 9000 Series Switches Bidirectional Forwarding Detection DoS (cisco-sa-nxos-bfd-dos-wGQXrzxn)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco NX-OS Software for Cisco Nexus 9000 Series Switches is affected by a 
denial of service vulnerability. The vulnerability exists in the rate limiter for Bidirectional Forwarding Detection 
(BFD) traffic of Cisco NX-OS Software for Cisco Nexus 9000 Series Switches. An unauthenticated, remote attacker can 
exploit this by sending a crafted stream of traffic through the device to cause BFD traffic to be dropped, resulting 
in BFD session flaps. This can cause route instability and dropped traffic and may result in a denial of service (DoS) 
condition. This vulnerability applies on both IPv4 and IPv6 traffic.

Cisco has released software updates that address this vulnerability. There are no workarounds that address this vulnerability.
Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nxos-bfd-dos-wGQXrzxn
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bbf2e13f");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74834");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvx75912");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvx75912");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20623");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/02/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/02/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/14");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl", "cisco_enum_smu.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Model", "Host/Cisco/NX-OS/Device");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco NX-OS Software');
var workarounds, workaround_params, g1_model, g2_model;
var smus = make_array();

# Cisco Nexus 9000 Series 
if ('Nexus' >!< product_info.device || product_info.model !~ "9[0-9]{3}")
  audit(AUDIT_HOST_NOT, 'an affected model');

if (product_info.model =~ '95[0-9]{2}')
{
  smus['7.0(3)I7(10)'] = 'CSCvx75912-n9k_ALL-1.0.0-7.0.3.I7.10.lib32_n9000';
  smus['9.3(8)'] = 'CSCvx75912-n9k_ALL-1.0.0-9.3.8.lib32_n9000';
  smus['10.2(2)'] = 'CSCwb07349-1.0.0-10.2.2.lib32_64_n9000';
}

# check BFD feature
workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['nxos_feature_bfd'];

var m_model = cisco_command_kb_item('Host/Cisco/Config/show_module', 'show module');

if (empty_or_null(m_model))
  audit(AUDIT_HOST_NOT, 'an affected model');

# Cisco Nexus 9200 and 9300 Platform Switches
var model_list1 = make_list(
  'N9K-C92160YC-X',
  'N9K-C92300YC',
  'N9K-C92304QC',
  'N9K-C9232C',
  'N9K-C92348GC-X',
  'N9K-C9236C',
  'N9K-C9272Q',
  'N9K-C93108TC-EX',
  'N9K-C93108TC-FX',
  'N9K-C9316D-GX',
  'N9K-C93180LC-EX',
  'N9K-C93180YC2-FX',
  'N9K-C93180YC-EX',
  'N9K-C93180YC-FX',
  'N9K-C93216TC-FX2',
  'N9K-C93240YC-FX2',
  'N9K-C9332C',
  'N9K-C93360YC-FX2',
  'N9K-C9336C-FX2',
  'N9K-C9348GC-FXP',
  'N9K-C93600CD-GX',
  'N9K-C9364C',
  'N9K-C9364C-GX'
);

# Cisco Nexus 9500 Series Switches
var model_list2 = make_list(
  'N9K-X97160YC-EX',
  'N9K-X97284YC-FX',
  'N9K-X9732C-EX',
  'N9K-X9732C-FX',
  'N9K-X9736C-EX',
  'N9K-X9736C-FX',
  'N9K-X9788TC-FX'
);

var vuln_model = FALSE;
var m_list1 = FALSE;
var m_list2 = FALSE;
var version_list = [];

foreach g1_model (model_list1)
{
  if (g1_model >< m_model)
  {
    vuln_model = TRUE;
    m_list1 = TRUE;
    break;
  }
}

if (!vuln_model)
{
  foreach g2_model (model_list2)
  {
    if (g2_model >< m_model)
    {
      vuln_model = TRUE;
      m_list2 = TRUE;
      break;
    }
  }

  if (!vuln_model)
    audit(AUDIT_HOST_NOT, 'an affected model');
}

if (m_list1)
{
  version_list = make_list(
    '7.0(3)I6(2)',
    '7.0(3)I7(1)',
    '7.0(3)I7(2)',
    '7.0(3)I7(3)'
  );
}

else if (m_list2)
{
  version_list = make_list(
    '7.0(3)I6(2)',
    '7.0(3)I7(1)',
    '7.0(3)I7(2)',
    '7.0(3)I7(3)',
    '7.0(3)I7(4)',
    '7.0(3)I7(5)',
    '7.0(3)I7(5a)',
    '7.0(3)I7(3z)',
    '7.0(3)I7(6)',
    '7.0(3)I7(7)',
    '7.0(3)I7(8)',
    '7.0(3)I7(9)',
    '7.0(3)I7(9w)',
    '7.0(3)I7(10)',
    '9.2(1)',
    '9.2(2)',
    '9.2(3)',
    '9.2(3y)',
    '9.2(4)',
    '7.0(3)IA7(1)',
    '7.0(3)IA7(2)',
    '9.3(1)',
    '9.3(2)',
    '9.3(3)',
    '9.3(1z)',
    '9.3(4)',
    '9.3(5)',
    '9.3(6)',
    '9.3(5w)',
    '9.3(7)',
    '9.3(7k)',
    '9.3(7a)',
    '9.3(8)',
    '10.1(1)',
    '10.1(2)',
    '10.2(1)',
    '10.2(2)',
    '10.2(1q)',
    '10.2(2a)'
  );
}

var reporting = make_array(
  'port'    , 0,
  'severity', SECURITY_WARNING,
  'version' , product_info['version'],
  'cmds'    , make_list('show feature | include bfd', 'show module'),
  'bug_id'  , 'CSCvx75912'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  workarounds:workarounds,
  workaround_params:workaround_params,
  vuln_versions:version_list,
  smus:smus
);

