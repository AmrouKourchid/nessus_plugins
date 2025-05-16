#TRUSTED 52de826e7516024e17656eca58f0c74ca311aea46476012b545efdde76e3d14109ba4aa7c856d8c375359c4ba7155feb9c8005c8192cffe6b733b4a9294aa49ca6085b3f3dd722b45fba15e2aa200be83a456c67b65e667e27841fc5705975abe83275625e0f391348d06f640f1473b19c30f721cbbe597b80c1ec016a9062419d2bac06fdbfc31b0dfe39e85ca778b28a12f9efe43f72b9b77b5b560a4017cfc77a5a0e375bd7257b8141662ea79bf9c5cffa6c9f3985c267f124ba04245b1141fcf40b25ef3630a9e6cf2061a0b0ec284842b9b1987d3c1058413f72d157e360232151afa591e38b5e7ab8cf385dcb1ac8a479a96ade4fcf32ac4f220b33f65e1881c7aa775a8e02dec4199aa01d7a7bd519fc0d5c924b54ed7c6e113b78ff6b0df8fb5f191aeb839e009227dbe5c6ec0d9152e6fc0fc37569233a89530456182c7dfa21c33e01e16fdf9e39f876cd378545e78a54b0b97ec8f358381064d778054e52ceb7de66d711fedff367af14f5f24d405f2ea70212317f5e22748bd12def46ecfd47e5b8c367951aded2bddf7e190586ea2b03c29f6a6b520a2627616054baefde0843fb4dfda05bd2221bae67cfd1b2527b90061a3df33faa78c002d0aa10a30f4230638b5eafcde7615bc5e5762d2b44333a144c9a58cfd50b9ed2f83e21c98e6c374db58868cb78f5afc3c3a38897cfea24a93ffcf67ab33b0b7a
#TRUST-RSA-SHA256 104371282fe430d8d0ba0ad14d1766a623507a9f3474d2a0dc5d6be85dc74b6363abb945e3a31e5c9870d7aaea3af1f59e205b6f5051c4445d3515c885bbc1253ef394f3f08db79df478a845f56643149b1f7829dc925d416f59bc63adc20c4aa75882407008a562b2147dc33489be681eedbbaec015e92c0320d27e902fd757e1b96409f481cf24b7f03b50b4d64aa5b74d1a615d2be8e32bbacc8984506192709e8a099240a86116bbce30b026b0050fce924ae53678a0f451da629dd37aba86632020df420b74d26bdc1f06b1bbd83fd32a4ab6fffd3e19d66816ae30368bb36f2879a18f0381627d3f057540d652406831b034389887a3373e55bfe5a0feeffea96e0d4fbdcc949d384eac2ca8cc9cc17c3dbad3fdacf74c07e421836aefbea2f4ed9820299a371e20d6b9cf86b112974a673e395f7a4caeaf949921aad76c49441a268d0934bdb8167a7a33394e9d4b98ba15a6c03ee69a42511e609b54695997fd232e960054a2645136c73a8d8f55154d951966945ca21f5077023d000aad01c9653eed7680aaa7c94946b7c0a0dc1eac812e2b3881e020ca617ef88ae9416d2bb4e3440571555da19243908f7addcfaef1367fc71d30b7fe679a7d9998d24328c14e7bf2a70e23a6ecdd7958ba4f07232192316e813c1031072066eef4aa1654ceabf189b887ccf3f66af1845a97e9721f7138cc8c25e9f42859b1c8
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(141171);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2020-3408");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt78186");
  script_xref(name:"CISCO-SA", value:"cisco-sa-splitdns-SPWqpdGW");
  script_xref(name:"IAVA", value:"2020-A-0439-S");

  script_name(english:"Cisco IOS XE Software Split DNS DoS (cisco-sa-splitdns-SPWqpdGW)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a denial of service (DoS) vulnerability
as the Split DNS feature's regular expression (regex) engine may time out when processing the DNS name list
configuration. An unauthenticated, remote attacker could cause an affected device to reload, resulting in a denial of
service.

Please see the included Cisco BID and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-splitdns-SPWqpdGW
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a2f37dff");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74268");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt78186");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvt78186");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3408");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(185);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/05");

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

include('ccf.inc');
include('cisco_workarounds.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');


vuln_versions = make_list(
  '16.10.1',
  '16.10.1a',
  '16.10.1b',
  '16.10.1c',
  '16.10.1d',
  '16.10.1e',
  '16.10.1f',
  '16.10.1g',
  '16.10.1s',
  '16.10.2',
  '16.10.3',
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
  '16.12.3a',
  '16.12.3s',
  '16.5.2',
  '16.5.3',
  '16.6.2',
  '16.6.3',
  '16.6.4',
  '16.6.4a',
  '16.6.4s',
  '16.6.5',
  '16.6.5a',
  '16.6.5b',
  '16.6.6',
  '16.6.7',
  '16.6.7a',
  '16.6.8',
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
  '16.9.3s',
  '16.9.4',
  '16.9.4c',
  '16.9.5',
  '16.9.5f',
  '17.1.1',
  '17.1.1a',
  '17.1.1s',
  '17.1.1t',
  '17.1.2',
  '17.2.1',
  '17.2.1a',
  '17.2.1r',
  '17.2.1t',
  '17.2.1v'
);

workarounds = make_list(CISCO_WORKAROUNDS['ip_dns_split_dns']);

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvt78186',
  'cmds'     , make_list('show running-config | section ip dns')
);

cisco::check_and_report(
  product_info:product_info,
  vuln_versions:vuln_versions,
  workarounds:workarounds,
  reporting:reporting
);
