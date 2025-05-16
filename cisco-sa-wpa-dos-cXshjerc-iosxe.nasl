#TRUSTED 7c3df77e7292d707e430f125d01991c376442055c991ea37347cb3fc4a02d234734eb7944768f22284ca0e568f2479ce2458ed73685404fdde428ff527df3dbf689f5c2d2225b8ed599a11392ebbdf54895785cf8756d8a209616d8e4bfbfc7ae314e37f2eab85dce37edd3d6de1f9c6d6a5a19720b2ac8394eabc5e59d7cc5c56655ccbf153e57550dd8896b02b8a335b05c7a6634c222cc39363e078eb5b94d9b75a91f794c4681ff77c6c1ea95c83f41c30b723ad69d65b3356d41b0484f7e6dd1d9c103aed5f9189dc08b06665f45675145d124c9d58161b0ff743597d4ba3796bbcab23eea47058695d22cacb8b7f0aebb70354ebbce91b5239aa80fb2cd6b81477893e7e113c66325e81b0dcfc44e4fa932b62340f48cd63c2752ffa0457a6b6d99848b56fb6c96bed187de183694a4e046fc0ded094d02b871ea63beb714a0e32233e45cb1260956962c9f38e21feceab1671ce2dd106339e334e6911f1a34f7149c426bec4bf9a18a8250278f2d3df8dc1b8673975cf3bd632b8508a47543b29ab6f8040177b96d7e5e4223b8c4b79866747a9762b3524167d379c35451e28d7cdc0993d1ac5d0fd72b50809370e770cf96efe9a8af005292890b309e991820ce55d3b1acd92ebd3d759143bad09928f68195df001cf4654c8b20188e8c5f1b53f636bd5e7d902930d92b81c5e158195f5774c66d510524a19b977eb
#TRUST-RSA-SHA256 3003f15904cc94a05f206d461c5f3083d0e41153557ca39ffdb8a2d6a8f42c39e32b788b01b4d88ed74a3cd9491dbfdc834423079f2ec5b0e44c2d1ed372ea1edac18395202bca0d78e2aee3058ef70ddaa1de1ec4b082abb08794b86e66b9d5c3b93fdb6ec6dd0b1f7f4385cd9260fff79fc62a646b6229c81fc565b54190067a9b655b037afda4f06237a1a54f84f52e4248b345001e38f221ee76e7197b9c6a9f898c8b423ff9eaa0bd087a37674b3fd91a28320eafcb1e66c47a21f1db0f228391aadf7908367a4a8a5d958bddac9a5b967ead7ac69d742ecf42841c825e381a5506bd67b9ef2293747f4998aad6f3102e82cae6b92934b9ccdaaeed20c7f6a5eb1af365813347710096bd57ff98715b4ea325adf2920eb0a5ce4b7e13d773ba7f43d96963a33ddec6e85a985f5ee099b7cf0907f10fb41d868c193e869e9df99a2754c793c38cbc7bd57b79b9d6394df5d17d3f15db9ecaf8bbbd05b11582a46ce1a11e100b565ca8434622666128b2a7675329db6ba095d0a7dd8bac5a1c3c1c9730038dd487dc716d12c28041b2b2d2bfac05dea83e4af53fa77ec309ff7229fd9b2fb66e33e5375fbab17fe6355c42c89d645eb95b22eb462c5a41c3297d3b5a511b67ebd1e73a2eb3966b00541c77a05c038701aa34d75ac511ca191b7ee7893fb53e80deccd6d7a7de1048d5e7c9bfde11d579854584b7a49a8be7
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(144196);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2020-3429");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr69019");
  script_xref(name:"CISCO-SA", value:"cisco-sa-wpa-dos-cXshjerc");
  script_xref(name:"IAVA", value:"2020-A-0439-S");

  script_name(english:"Cisco IOS XE Software Wireless Controller for the Catalyst 9000 Family WPA Denial of Service (cisco-sa-wpa-dos-cXshjerc)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, IOS-XE is affected by a Denial of Service vulnerability in the WPA2 and WPA3
security implementation of Cisco IOS XE Wireless Controller Software for the Cisco Catalyst 9000 Family and could allow
an unauthenticated, adjacent attacker to cause denial of service (DoS) condition on an affected device. The
vulnerability is due to incorrect packet processing during the WPA2 and WPA3 authentication handshake when configured
for dot1x or pre-shared key (PSK) authentication key management (AKM) with 802.11r BSS Fast Transition (FT) enabled.
An attacker could exploit this vulnerability by sending a crafted authentication packet to an affected device. A
successful exploit could cause an affected device to reload, resulting in a DoS condition.

Please see the included Cisco BID and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-wpa-dos-cXshjerc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?50813faf");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74268");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr69019");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvr69019");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3429");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/14");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/IOS-XE/Model");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

model = product_info['model'];
device_model = get_kb_item_or_exit('Host/Cisco/device_model');

# Affects Cisco Catalyst 9300, 9400, 9500, 9800
if ('cat' >!< tolower(device_model) || (model !~ '9[3458][0-9][0-9]'))
  audit(AUDIT_HOST_NOT, 'affected');

vuln_versions = make_list(
  '16.10.1',
  '16.10.1e',
  '16.10.1s',
  '16.11.1',
  '16.11.1a',
  '16.11.1b',
  '16.11.1c',
  '16.11.2',
  '16.12.1',
  '16.12.1s',
  '16.12.1t'
);

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['dot1x_psk_akm_ft_enabled'];

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvr69019'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:vuln_versions
);
