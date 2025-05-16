#TRUSTED 42fa4c2e3208c84c779afc506a6176e5a21519acfd5f2051a1b1b4f6c7eb703e8bd68e77434f6139b9cde5b78b242b224410eaedcf4e9a5a2aac9c22b00c426f0e9bc99ae43685014babc6224b10adeab33aee407d6b5e50c54176165f8abcd7310f186365195d262106fbf774acbcca49c7513f888438f737543a2e9ad504e8fc86fe1d4074b9b8f2bd69251b66f3871ea85d653c2ecb0fbb46d798f4b6075624ed73de2e00140c1dfa8fa06707b2f11e94f7bf9ddcc1068f2b4fbe800f749848cbfbe562367505402f322e3e49a95fded3ca2648f5b8eda0462c6f7c3502e9d2187f573cb01df92aa7132cb43d24949a92ac9ba22b54b83b917d62d18013a00c767fb45c9a1b9e3dd4380773def7e33ff32ff7cbb6aa40ce5b20b9ee454f287ffe873de32165f5a0c833b1d816d62d290e9582a127f9ae42f8c6f3b03af66d845ab27e4dd8c58d6675e64d8d6443dcc6ff200cc7c55ff5e42dc261b95ef052287662422bc060defd54d9fad33c43a673c394a8231fe90cb587259b5d7b0fe71c739d7366e8e46c39f9962d84279ca3553848aa41b1846fcd72e85cacf87dc7810c0032343ef2853b829930b25f81c0e7cb766e47792846d7f5251bb0da30acc679babaabea0dff247213c08d4693bed8d0b7bf69e28f4ca83f06279bf60fb1f4b24529b576523e997cd37439403732b1aefa9e1745aa7ceb3e565572e10052
#TRUST-RSA-SHA256 0c06f02f1362bad05dc7daf800b1fb35070d9ae9d682eb784ee17f53a9a8d4e994f9f962046805cff71c06b82f1e49eb1491c70aef6131eb040d72295a5d40e3617ed33da7a4214282c72da34a4831e6bd047b29640ae97c2b72c780388be0422c04d4f194913d02e43021185421da698983c0eac30696f01675969461668aff55a730db6ed181f7e80312e6c02e5de1a429772b1a93a05d63f3623d04995cc865c3d45bb6fb8e6f678bf3c873444634d29189c04dcc95b1fb80afaf0804211001a7dc55d13fcfa2e14ea751aa4e3795c8f4a567aa60754ddac262264f749391646253e14f10a16450feec2646e9af155389444d09fbd055e21dd2c6d0bc5176b82e668d2e68167f500c11c92a1374766a7898af04fe58b0eecef9ca7146de2cf1a5fc6e2f8a4b4a11ca399f68b8ce45247882c9aaa230d6f0f446b78fee8e467fe90c1ae06bcd566ab21e7a9fe675af67b6e4d395a9d3ef47bad2e5ac595ccfe5dfb55d9668068f9bae4b00061d730057fb544328c552575dc91365396f4e495ea83478e5eed2252b6429c668f31cdc41332145be34343704a9be2d2b941af8d92270e472c91a5f393ac407e6737c4fcd123efae1ca865cef1566cd450a7c90306d07b4af5894d0b7e4c04088bcd7dfa797456f88a80c8639fa6aaf585bce8ec8a77406b7ec7abb1d7c24122f31ec2055cd7a2c715c40c9e552acf2d68e97d5
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(134889);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2019-12655");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvn02419");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190925-ftp");

  script_name(english:"Cisco IOS XE Software FTP Application Layer Gateway for NAT, NAT64, and ZBFW Denial of Service Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A denial of service (DoS) vulnerability exists in Cisco IOS XE Software FTP Application Layer Gateway for NAT, NAT64,
and ZBFW due to a buffer overflow that occurs when an affected device inspects certain FTP traffic. An unauthenticated,
remote attacker can exploit this issue by performing a specific FTP transfer through the device. A successful exploit
could allow the attacker to cause the device to reload.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190925-ftp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?35424e16");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-72547");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvn02419");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvn02419");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12655");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/25");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}
include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list=make_list(
  '3.16.9S',
  '3.16.8S',
  '16.9.2s',
  '16.9.2a',
  '16.9.2',
  '16.9.1s',
  '16.9.1d',
  '16.9.1c',
  '16.9.1b',
  '16.9.1a',
  '16.9.1',
  '16.6.5b',
  '16.6.5a',
  '16.6.5',
  '16.6.4s',
  '16.6.4a',
  '16.6.4',
  '16.3.7',
  '16.10.1s',
  '16.10.1e',
  '16.10.1d',
  '16.10.1c',
  '16.10.1b',
  '16.10.1a',
  '16.10.1'
);

workarounds = make_list(
  CISCO_WORKAROUNDS['nat'],
  CISCO_WORKAROUNDS['include_nat64'],
  CISCO_WORKAROUNDS['iosxe_zone_security'],
  CISCO_WORKAROUNDS['zbfw_policy_map']
);
workaround_params = make_list('ftp_alg_disabled','ftp_zbfw_policy');

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvn02419'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list,
  require_all_workarounds: TRUE
);
