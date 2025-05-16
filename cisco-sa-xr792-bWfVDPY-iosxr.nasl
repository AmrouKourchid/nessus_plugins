#TRUSTED 191247d123c0c2c61103459a82d80f29ba658d09f04cf19ecb0386166913a3ef83719927d9e4ed6a503b417edd0919bd9d1fe30063bafe3254a42273218d1a127fd0ec5d403a7e9bdb71bdb5d37ed6523dd25a66191f65b3f06dfd986f18a213455064990359be25a48b08150a4b3417324001c5f9aa17921f1d8d36f3e87385406110582c14aeb5cdd6cb2a234cca887cb1a2d39dd0bb365a4634df8addfc662869996c4c0d23def53b75bca11c60e811989144e8f51d337ae681186fab0a3f73cae64928c5822c5c7315293e404b727cff4cea000d37fc5cee43ee0a39d603f715f2067f09ab62e281719fc32c35198c54f922bb3808f1ecc48777f53d88e63e15d1abc47c31c2b1fc98a169be9622c70c731f5e0db8eeab9b20df99fa6e1de8f5227571ec2530e0efe701c39970d4c3bca8ba2d7d842c15d48b255a3a39ec09b8bcbe996f6153982a23d18094876ca5c14c1ecec291a2f0b5c639d4c5b0bb7665fa60834a3f4734b90ed1771ddcae68deb99b7ff35d871ec62f1c76e95cac0bf85a54698c7f7ded9bc1d8f6bbf1a7ff57ae5003f013fc3621504dd597e18e051ed9059b2871cd37ee6564b705b06c10ab4dfd5f7188d77de62c905dfd5d7b62857341240407666a6991870d36cb4f4c279a6aa52419c59568f1b40cbcd547ad535b45e2895eb43069d6831a4f64c48d6747c5e4247d4a8a31cffc8b78bcb8
#TRUST-RSA-SHA256 a1a842ac8c915e4864d77f108d28d6af53eff482320b5aaa806782ab250ef2d0722954b3f368b3c019a67da44fc10cc24920eb4bc7779a46cd53b98f481e599890898434bb6287fad14a6367113d73303aa7cd8e8163f2aa77e335e29640e6fbf64cdb42c90e70418dc4c03974ef60c53db3958ae7402b15ac162fe23f2678dffb1ba8d3ef38bb890b116a65beb1a4c686bbde9304d1ee636ab3cadba55e9d7e40fa568b9531033562bdc628b67ca531fabba1f93e5b8ec6e9edb1f82c1fee35f1466ed72197543d1bd089277c60d124408d0588f73cdbcf094d25ee2160217513936529a7d69af197eaf395fc9492d9f41024c03177ca62924e8c31ff080195284dea684113aa1f7ac2226c10b93d0b003ff6f50a55be7a3b6229782f06c9c251a9e94ae2436a9286d35d473da30ad45bd3ca8104d791ab221fea22ca18c69c87154d84417bb70d33288af6ed5f25c427caa57bc5419b7dde7922022244cdafa22043efe2ffbd9f3375ae472ea55ea6d0324bba582a2eeadcb0997376f1a2c564dad6659b4477a19a72ed0736883bf851d8927e20bdf0c4e275e56ad2244e0b49318ac512d07bfb0c2fc34edecc427cb1496b02d3f4b5166e2094d48bf282ae4082f5af4c6c624a47b95095ac981149e5c6eb6d473c874c6b19db3f9a02fe1b6dc58fe374e3744b4f11b30b4af29065ece7a35379d9bec9ab289606ee6d672f
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(234055);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/09");

  script_cve_id("CVE-2025-20141");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwf89955");
  script_xref(name:"CISCO-SA", value:"cisco-sa-xr792-bWfVDPY");
  script_xref(name:"IAVA", value:"2025-A-0159");

  script_name(english:"Cisco IOS XR Software Release 7.9.2 DoS (cisco-sa-xr792-bWfVDPY)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XR is affected by a vulnerability.

  - A vulnerability in the handling of specific packets that are punted from a line card to a route processor
    in Cisco IOS XR Software Release 7.9.2 could allow an unauthenticated, adjacent attacker to cause control
    plane traffic to stop working on multiple Cisco IOS XR platforms. This vulnerability is due to
    incorrect handling of packets that are punted to the route processor. An attacker could exploit this
    vulnerability by sending traffic, which must be handled by the Linux stack on the route processor, to an
    affected device. A successful exploit could allow the attacker to cause control plane traffic to stop
    working, resulting in a denial of service (DoS) condition. (CVE-2025-20141)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-xr792-bWfVDPY
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8571b2ec");
  # https://sec.cloudapps.cisco.com/security/center/viewErp.x?alertId=ERP-75548
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ecfccd38");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwf89955");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwf89955");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-20141");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(770);

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/03/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/09");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XR');

var model = toupper(product_info.model);

# Vulnerable model list
if ('IOSXRWBD' >!< model && ('NCS' >!< model && model !~ "5[4][0-9]{1}|5[57][0-9]{2}"))
    audit(AUDIT_HOST_NOT, 'an affected model');

var vuln_ranges = [
 {'min_ver': '7.9.2', 'fix_ver': '7.9.3'}
];

var reporting = make_array(
  'port'          , product_info['port'],
  'severity'      , SECURITY_WARNING,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCwf89955',
  'fix'           , 'See vendor advisory',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
