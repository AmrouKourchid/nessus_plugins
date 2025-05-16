#TRUSTED 9d85ee2ca1f1bb30436da9515586b68153db3826f682476a4c4a92ffa07bdd2c8a9313ef7ba2568a7465ca9951c5e07d3a41db4f6d154de14eb0432dc052897054053da7fa0c326effc53583ef5cee989d712c8dc077dcc9e638a413052dba85470d295ae60dea03ad9babcf4d41d82f4aa1f4c3a5dce800f53e077fe0cd30448012c9c4d5d9c1a85c8c74f3183959d509fd0ae7dbfccc060a9b700faf5cb17c67900fb45d6fa125e42e8cd5b5fe20d9184260b6575336835726a5dddf479fd9cbdc7928823bb7e24493f8d7e03a25dc00101415d4af3d049b8bb030b371d54f7804f55b2a85dad8a2bbf5626cfb76611f6b0e982e20c265b8ddf0a5397de1735e7ea92c68d3160fc8dbe33083f8a5b1ce9394531eb07415afa83d416e56d502fa60e9fd03bf0573a94249c166a62956b875f6575c41eac9b516c10f22631d2084bea44ae8885e373716cc02ed57781bc5b1159e8f9b6f4707d1e0944e88dad6c9c88c440ecac9fcaae472e655d7de869e34934e6ca63f8d1404b6851e70adeb02939be1ffe8cc7771ce9d769091628e8ef2953873649106c729e4102b99a04cd4bfae2d7c26cc3f2e2dad6118b20648ab98180ec5e050c8e4828a6cb720d301cc329fb49c32ef93aae7313d54d0a7f6d48cf6e3f754f412a98b3230cefac76d55ef530391ebf1ff0ffe3aefd5cdb646bdc8ff8d37c2a4ca916862c12130341a
#TRUST-RSA-SHA256 62746e3c82dd203d98524deef58afe2b133c33faca8249482778818a63f968d9cefa8b6838b6ba3143740d009096cef11e0b1994a6c922b9cc90c5f5319b4133aa811bd799b420e7a994573aefa984b4d02efb997599cb35c878b04e3ba700ed0b61bf5b40dc93e2fd40d02c41ecd28e6ee547f70032ed422a00b1be522d502baa15bfef924d6a14c541f4755f0acbcee7f53922581ddb2eeb3722132d40c16d695091b7d7ee8092cd0e6f78a5193c5761e33cc3f18a18daefbbf7d82803391b97a8baec2fce790c9270ecb61fc73698539cdd7785a528ceb874b19a05a8124f294b4d7004f13e834e068cced4a9cbe5c42dba3f62326fe62adf78309507d1ff6eeeb627f09fcc78ebc778bdea8e8035cead6d8b1ba2c7a00ceb1b6b92de58c39310689593f4d862f77033574f23c32b6b4b2ec9ee06e94e29a417e6a762a764b90cedbe1ad84017cce34035d4ce991f0ce31e72ad5c09cd8c73d2ee60568b0017556e9278b090052d61e1c0cd7f32ccfa89ea190f3300cd3b6079040f472b24f54110af46c07ac22feb73c0a8c32cab10ed65538cd4442cb7f0e570076776d288b0752854c9329b49302035fe761e6fb75b29e7256ddad16dd643ee40dd9af83ebe054c995d106d96fa1c05e15ad14210db0f2faf92da49379d33614faebedece93fbdbb0a4b5254ebbb047acd4f3076cc2d6407c4b745d7e6e2fcdf5f939ff
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(140189);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/08");

  script_cve_id("CVE-2020-3397");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr58652");
  script_xref(name:"CISCO-SA", value:"cisco-sa-nxosbgp-nlri-dos-458rG2OQ");
  script_xref(name:"IAVA", value:"2020-A-0394-S");

  script_name(english:"Cisco NX-OS Software Border Gateway Protocol Multicast VPN DoS (cisco-sa-nxosbgp-nlri-dos-458rG2OQ)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco NX-OS Software is affected by a vulnerability in the Border Gateway
Protocol (BGP) Multicast VPN (MVPN) due to incomplete input validation of a specific type of BGP MVPN update. An
unauthenticated, remote attacker can exploit this, by sending a specific, valid BGP MVPN update message to a targeted
device, in order to cause it to unexpectedly reload, resulting in a denial of service (DoS) condition). 

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nxosbgp-nlri-dos-458rG2OQ
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?23245ed2");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74239");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr58652");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvr58652");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3397");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/02");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Model", "Host/Cisco/NX-OS/Device");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco NX-OS Software');

if ('Nexus' >!< product_info.device || product_info.model !~ "^[39][0-9]{3}")
  audit(AUDIT_HOST_NOT, 'an affected model');

#  not 9k in ACI mode
if (!(empty_or_null(get_kb_list('Host/aci/*'))))
    audit(AUDIT_HOST_NOT, 'an affected model due to ACI mode');

version_list=make_list(
  '7.0(3)F3(1)',
  '7.0(3)F3(2)',
  '7.0(3)F3(3)',
  '7.0(3)F3(3a)',
  '7.0(3)F3(3c)',
  '7.0(3)F3(4)',
  '7.0(3)F3(5)',
  '7.0(3)I7(1)',
  '7.0(3)I7(2)',
  '7.0(3)I7(3)',
  '7.0(3)I7(3z)',
  '7.0(3)I7(4)',
  '7.0(3)I7(5)',
  '7.0(3)I7(5a)',
  '7.0(3)I7(6)',
  '7.0(3)I7(6z)',
  '7.0(3)I7(7)',
  '7.0(3)IA7(1)',
  '7.0(3)IA7(2)',
  '7.0(3)IM7(2)',
  '9.2(1)',
  '9.2(2)',
  '9.2(2t)',
  '9.2(2v)',
  '9.2(3)',
  '9.2(3y)',
  '9.2(4)',
  '9.3(1)',
  '9.3(1z)',
  '9.3(2)'
);

workarounds = make_list(CISCO_WORKAROUNDS['show_running-config']);
workaround_params = {'pat':make_list('address-family ipv(4|6) mvpn', 'feature ngmvpn'), 'require_all_patterns':TRUE};

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvr58652',
  'cmds'     , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list,
  workarounds:workarounds,
  workaround_params:workaround_params
);



