#TRUSTED b10f4f0289d926c1b6539b65bb5311832cc9a39f34e77395427c47c2fabff9f5aa58715d01ed5562753cbd64b059c28850c5095ab79d43c8ddad4bc1f0aea815e4a250678c923a0552be5771105c2b80430ef0a7348877461d0e52969a5938f2e0995e2043405c0bf7a095363b2038378d44dcc5d8d16f605bedab7296bcb19d28015fc1b19b7bfb169a69602538cab0a1b33c09983388968427917512e0d9fe98fddeb80f4eb51932abded68988f5981b0fc4635a7a734076d3f4598b4257403c116fae9cb5abe6275d587281fc8f52ae49eee9ea0460878ae79de409ea2352ab9c4f1e7c28d143b7389d2cbef86ff40990392095ebca692e59b625ae1dd95b744936aa10d3f02a0c3cfb80c61c8d9a05f2d71962721c02dc04ca60f608c84833256607bfaa92753ac566b35d8b3df1350041e35a691ee4926e2e0d3faf90ba3297101c3198bcd91ce45a5b2a1b66104a90a053df59f489a0eab4a24cb5c991ac355d251d1171db8169719795eaab2d15b947b478d5ede9b846e457f211034a065df49adab6e1db7a68f00ddcd307f252bde472a1205090dafb82a33c01466e7f94ab199800775df950a59b4de5f3c7bce1f23ee505233da65f95034631e8370d413afef436d7e54eb6fc547c89a52eed63e60fc128597a8b019b3031477ac1234c54629ce26ea167a0df7f0a0b4dd7a0f5deef377c4b06c94038c9efb0a607
#TRUST-RSA-SHA256 6530146e992267be01e7900ca5c1d424b96a7df7de532b3cf821e34d7da4bf625fbe0fb5c6d8dcb4743b9df33bd045b503c433aff688a41370091b03c5ca667586e17eafe1945dfd777e2badb6f9e11c5b370730eb2313363415814265d2a10d6b5af95d597d618516543926909c114ff9435b34e66c3386f4ddd6b531de896a87da5853eed5ea94f3262ce8d714a8151fddb34f1b95ccc1b8babcf35d5e789c4a2e5eaa27d91959d5f72d19d3f441a0e962bb8868572bfef957a8158cadd27c07a958a15d9dd1610ada2e70df017b585f21871ae3b15105dfbb5b19141fb8750aae72b0e086b03c790d3229868b789fd516b56164b178512bbfcde9c6f78284403e7a1023e11887a10daff841e5fe8cf619e995a1f215e34759fcdaad8e011d99da27a15cd14c7b8e29a6fa10a5f6ce5526404a6329484901a286af5548c42c14b6d37a0afbd9ff0198921e9865b51c7ffcb9e4644679e4b45e112a999892033f5f42492e9c37772cb62e96c212300fde98c73d22af06d0a92ff774f151e56f8676b8f03c27770c788d595f0da928f2645441d833402ad9760fdb7162acc22c73f82d8c2058ccbb6a21ff37fe55e74f1a0457597139a409b72d507cadc31bd2a61691bd33106fa4c98ad1612a11c4b18a8063247b71ee499b50c0446c409aa3f8335e19102c3e456818218d4d142a255c5a2d8c2b3ffa789f89862547d46aaf
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(141499);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2020-3407");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs72434");
  script_xref(name:"CISCO-SA", value:"cisco-sa-confacl-HbPtfSuO");
  script_xref(name:"IAVA", value:"2020-A-0439-S");

  script_name(english:"Cisco IOS XE Software RESTCONF NETCONF YANG Access Control List DoS (cisco-sa-confacl-HbPtfSuO)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, IOS-XE is affected by a denial of service (DoS) vulnerability in the RESTCONF
and NETCONF-YANG access control list (ACL) function. An unauthenticated, remote attacker can exploit this, by accessing
the device using RESTCONF or NETCONF-YANG to cause the device to reload, causing a DoS condition.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-confacl-HbPtfSuO
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a1e90eb4");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74268");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvs72434.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3407");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(476);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/19");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list=make_list(
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
  '16.12.2',
  '16.12.2a',
  '16.12.2s',
  '16.12.2t',
  '16.12.3',
  '17.1.1',
  '17.1.1a',
  '17.1.1s',
  '17.1.1t',
  '17.2.1',
  '17.2.1a',
  '17.2.1t'
);

workarounds = make_list(CISCO_WORKAROUNDS['netconf_restconf_acl_size_13']);

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvs72434',
  'cmds'     , make_list('show running-config', 'show access-lists')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  reporting:reporting,
  vuln_versions:version_list
);
