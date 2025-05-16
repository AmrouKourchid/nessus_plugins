#TRUSTED 8e5467f06d378976a9552ae617b26ceb63dc1a22476cc8ea6863fc334983a3251ebbf7aa3cd89d9486e3f0a3f61cfc9c9747917aff931235372a930c38b2144abf8c771f26d71341f61ff0e47acc59a89f9b32291ad261f19b6d71dc1397e24456ad7810042e5a9990e7f16b28e2a6905e0f3e5791f074f8b28b40d74b77affe58726b2b57fdb2bdc281f5db787135cd98316689a39034d5d6c19bcebf94c75c990b17ed19495010b6b625c9cc5bf411d2d8ae45860c4a509799f0d6197238ffdda905c6d5a85cdf4bd782a82124f7e9873803186b25647efa550b4b169362ad9af016f36281b7677f71be000e457b3937a66e2f42d5542ab59e08be480c2beaa7bc384c3ac4a3dfb7962b3c09808a21e72eae8787b68580d85d51b4c6507d3c30fa01e0084e92eca1981ff7f7a325e5c6276a825add412e174f63c01455812c7ef21fdf14488e37153e8d885861ee2b52290a2af406ba3bce45410b97d7b78628a67fc171a66900629a49040310b1e3f99787af3d4e1503d7e6a634ab17e74c2aec6c15139855ad52ed998e6e975d895bc9cf0e32694cac3005405c61e61af3b83e98fe44600757e6457a3a902441cacb3f7dcad1fc7c1250b2dc930746fe5d4f345072874c4bcc72738861769c8e784b7b7ec4073a1514260d8ff550c65888ffc1354baa85b084b2d14ab853bdd71cc90ec780cecb814a3b45fb0812cdfbef
#TRUST-RSA-SHA256 47bbcf51f238056b3f01bbf37468a208d584009ad169967f2b2c82e93a2ccb6222a34060d41672469a7d80215ac5808bcf7f4f120cb161b29142fa911bece5efe10562e020a600d08fad613940cc44347bc6de2dc06143f149971e05f9930ab0e1041fee44e62853d3f35c774b29bf34dc74954b1aeaf2f211a1a8b55e1d007ef05eedd9bed7a98f497c12246f8dcb4b02af82afb6cb71a13ad1804fc2cd26c9e31172450a3ccf35c7f2d7d18bdcef6c1433b5b716d86bdfe15903881e4a2817c1e1e6f7fc15bc5cd2a663c79c541c88f21b7e192ae7887ce10b9ee5ef53619999ac81a9357a79eb16d012ee53593a3ca7117dd1fe6c1c9a045ea3ff10c1b6c1e1a43760f17e96201f7967ce77d6bd212b912fe1f7eb35aebae0fd96e8376ae14364bd5eb8e643ae554c8c12fb0752d00fb746fb28321f6b34f0e43ab7745ddc12a1316c87d2640463d55ee64881f7c29a87b33c235408b0e1e743944aa7aa4c8002e0031ec6342f04a70a3a254e1780531a370332329ca5203d8db3c66e6c6d1c9687e9d3efe591ecd782aa6661859db21fa56854aed901be1744f298f9706cb264c46ffcb825c5739be7ba0734c5c013a431866f07c5babb5dc0fd723670795cb9fc805254f02c15121bba50bd886af7fed30dd43094a3ca3e21d5d4a18f1f59d9888eeb09317a3073b17b7e9df1f75ff8c4b704eba98445fabcc06e07a652
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(141461);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2020-3359");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr57654");
  script_xref(name:"CISCO-SA", value:"cisco-sa-mdns-dos-3tH6cA9J");
  script_xref(name:"IAVA", value:"2020-A-0439-S");

  script_name(english:"Cisco IOS XE Software for Catalyst 9800 Series Wireless Controllers Multicast DNS DoS (cisco-sa-mdns-dos-3tH6cA9J)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A denial of service (DoS) vulnerability exists in Cisco IOS XE Software for Cisco Catalyst 9800 Series Wireless Controllers
due to improper validation of mDNS packets. An unauthenticated, remote attacker can exploit this issue, via a crafted mDNS
packet to an affected device, to cause the device to reload.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-mdns-dos-3tH6cA9J
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0c17f0e7");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvr57654");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3359");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/15");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/device_model");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

if (toupper(product_info['model']) =~ "^(C)?9800")
{
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
    '17.2.1t',
    '17.2.1v'
  );

  workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
  workaround_params = WORKAROUND_CONFIG['mdns'];

  reporting = make_array(
    'port'     , product_info['port'], 
    'severity' , SECURITY_HOLE,
    'version'  , product_info['version'],
    'bug_id'   , 'CSCvr57654',
    'cmds'     , ['show mdns summary']
  );

  cisco::check_and_report(
    product_info:product_info,
    reporting:reporting,
    vuln_versions:version_list,
    workarounds:workarounds,
    workaround_params:workaround_params
  );
}
else
{
  audit(AUDIT_DEVICE_NOT_VULN, product_info['model']);
}