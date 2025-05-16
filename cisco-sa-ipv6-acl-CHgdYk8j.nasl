#TRUSTED b21e25b5021f70baece755c45beebe414b15e3139af6f8944cedc0ce42696703c331b7881e7a95a1abcf685a6fdc9890af8b19c13de4be96b2c187b3f4a5f653ba457b088bc1d6a20a16a07387e8e009a0d5bff468dfa62e36160a34a30fe35c5b4bc440b39841b4ae7554e30871c8314533141ab9eff253c7601f88b69f40278e719c36b1ff8e78648d7552cf636b52a012636c19c6ec4341a2e09344d89db60205ffdcd1f5403be03c628fe0b62da0c78f7490619af6cd826ded140205219512d2be8da907195828a57938eed849ff0ddafbe484056c29d5bccf364356896cf747a571ae87e109dfb680d34885649eee5aef09d832d7477e65f7423ccdf4a7131fe70ead1f3d550c3561e0d79f98f47bee807bf057b663886bfa08b0502c796d168967c5853f8ba5509480e90578f0bdc1dc70ae8fe0e63ca967e38cb048a4fd006bd473359445962a274bb6688f7b218e30bb5b385aa1f8f18d46d027d5ce016d317a705133ba29585332d600ab38712c0d51edfdf5d222c6ed931a6cee9c236f61849435c3f53d2fb2cf73e0283687b8d6d851cd98c68b812486a7b7c049381bc221efa0a06b43dbbb4871afcdf38d70b8d02aa692f33fa20434c3fe6b5bd5e8b53254b1218a0a72decd8dffa40bb02f7ad77b9142cac8b7b503c506d7f62083a01eb69ed39e34aaca936e2c712275dfafbaf5cb15528562daf42e10a379
#TRUST-RSA-SHA256 b090a840468d253f80cb37b1bcaa2ac71dd5a61bcda63af8fb970014b258683ab9f6e279f05fbb3286c0f6fc5605bfa3a275f2fcf8bf922a04f811f78a8300a864f9690e1092241729417bee23f0b7adeb99b34f4f675006a4657f25728d8ae87d2a91ea800052fd6f0d4de637adea777f6e09fac65080eb5aaf26ffa33a69db9f28af2c59f9f2314743f7c28b1edf0ce05713105b4ac248f9722362adad935789ba71d43dff676fb96f3800145448751c0c1904bfdfa59934fef1bb2d4beaba01a7297375bd6939ca3a3600f12bf6bb3873eb8696dec2c7df6732b6ade05516cde42adfaca6fc583893d1ffaa3c0fc9be18efe6e4e41c04d507682df9b67e16a898efc59f0f542024d75bef41b483f989d967a3877956ae7b4c8327bdbb944c9b76068d4871f2cf678c3a1e8674b88e2ac235df2cb816069acf19f77e93cbadb2f93edf82aca39825ed813b2fdebff23370c70b147a783e1ed86e8f4653ba64d6ed779fa3f7133ac8b59edf6e66c21d9d3fb7c6836006d83295212c4d6f5ea6f5e0ef3f4cce39af298e74f4fae7f07c2d824c09ed0417873131f748f0388ce5efc62c78c3d85fac2d6f324eae29f9aa574a19c4f2a4447a9e389f5efb562b63f1f09fa82ff37e3f8e952eed989c7f9b09ea971e46c9cffddb05d56d1beb3c8c4c55cea100282233e17b586e6fe5327d34b595bfb85413498ecf34ef83f49b09
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(146481);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/06");

  script_cve_id("CVE-2021-1389");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv45698");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ipv6-acl-CHgdYk8j");
  script_xref(name:"IAVA", value:"2021-A-0073-S");

  script_name(english:"Cisco NX-OS Software IPv6 Access Control List Bypass (cisco-sa-ipv6-acl-CHgdYk8j)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the IPv6 traffic processing of Cisco NX-OS Software for certain Cisco devices could allow an
unauthenticated, remote attacker to bypass an IPv6 access control list (ACL) that is configured for an interface of
an affected device. The vulnerability is due to improper processing of IPv6 traffic that is sent through an affected
device. An attacker could exploit this vulnerability by sending crafted IPv6 packets that traverse the affected device.
A successful exploit could allow the attacker to access resources that would typically be protected
by the interface ACL.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ipv6-acl-CHgdYk8j
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?76e17295");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv45698");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvv45698");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1389");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(284);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/12");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Model", "Host/Cisco/NX-OS/Device");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco NX-OS Software');

if ('nexus' >!< tolower(product_info.device) || product_info.model !~ '^(95[0-9]{2}|36[0-9]{2})')
  audit(AUDIT_HOST_NOT, 'an affected model');
    
if (product_info.model =~ '^95') {
  version_list=make_list(
    '7.0(3)F1(1)',
    '7.0(3)F2(1)',
    '7.0(3)F2(2)',
    '7.0(3)F3(1)',
    '7.0(3)F3(3)',
    '7.0(3)F3(3a)',
    '7.0(3)F3(4)',
    '7.0(3)F3(3c)',
    '7.0(3)F3(5)',
    '9.2(1)',
    '9.2(2)',
    '9.2(3)',
    '9.2(3y)',
    '9.2(4)',
    '9.3(1)',
    '9.3(2)',
    '9.3(3)',
    '9.3(1z)',
    '9.3(4)',
    '9.3(5)',
    '9.3(5w)'
  );
}    
if (product_info.model =~ '^36') {
  version_list=make_list(
    '7.0(3)F3(1)',
    '7.0(3)F3(2)',
    '7.0(3)F3(3)',
    '7.0(3)F3(3a)',
    '7.0(3)F3(4)',
    '7.0(3)F3(3c)',
    '7.0(3)F3(5)',
    '9.2(1)',
    '9.2(2)',
    '9.2(2t)',
    '9.2(3)',
    '9.2(3y)',
    '9.2(4)',
    '9.2(2v)',
    '9.3(1)',
    '9.3(2)',
    '9.3(3)',
    '9.3(4)',
    '9.3(5)',
    '9.3(5w)'
  );
}

reporting = make_array(
  'port'     , 0,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvv45698',
  'severity' , SECURITY_WARNING,
  'cmds'     , make_list('show ipv6 access-lists'),
  'fix'      , 'See advisory'
);

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['show_ipv6_access-lists'];

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
