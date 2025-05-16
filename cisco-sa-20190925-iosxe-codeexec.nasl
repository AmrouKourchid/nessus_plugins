#TRUSTED 646217fc248387816c9b385413c84455a5c701e62431350113bc74df5ac1f154f7d6524190ebe32065c9b12b66781f1ea0834a9b39d25be66812bdbd8eb0342648006008a479cb81c2f57007ff1ae67b321bee1208436ace1a13151b3243b71a92389aab1b7e23f131c1064982b56cb01479e3106558ab1e381ca12d3bfbf114432a2027708f3cc11d8dc6eb9c214a915cb2903d3cfed8968e8347d1941df47b67981353faf13b112af68ce7d7a99a811125900869f249a1ae92628e8b2beb248c3ad4c96089b8c118e6d1ab241bf632326a6475fdfbe062257b2fdf951d1cae834023e5c00563c6f3467e81454dea1469788c8925ecf43ebb350caad3c0d7c0734419e6ec41f33aaf932d1a7510f8763034848f4ab29e7c9a9717b99f679a3cae8a06580c6f5e7df914cd8123bdafc4d7ab7c595cc78e3d10a1046499fc5856630f1fc3be211be95cf68b096c8d2114410a0d005e3d69cba31c771bc8ecf903b7addeb8192bc3bc8175c557e6594ab0491b8c1eba40c8b8f9032ade29240ed94b1d0f1bcb2af2938357a983502fcfdb29e5e164168fb9f53205d6778ebedd6db438810b0e15b2c676de84f9250f1a3bdbc5995cd8f33bc6b04932573a48e3ee17ee41fe7666d6151c030a0609a31de51c3dcf7f8ae4dd50b711a9378e39aef391cf9cc8c5bb9db17350a2b35d91cbd24b984ef8da0fc19ec4ec3f1138427f84
#TRUST-RSA-SHA256 b011848be8474505ce354e62374b6300c5343ffac6bb89e213eebacae2ebb11ac9a0b9403b3d5198f709acd1b8260bb5c4c6d69faa0643002417e974421125a1b878c10e5f04d7b2232f2a75a1de442bb00f96ae7901c96e48d6ded138d409c0da8f22300264425e7fb86f428ef33a129df7669798f5f8725cc8fcab707ac7979d9607671f677f67ef5e02dc27dc64a9c32fe9ec1b04d925e7399a2aba1b19a81826b0275ec9a785e94fdf36374d5057ef0b5ca0af16c9aa01850795716b11ae35c83178af656fefbcd1ffe6df1ee28da22144ff47e6ed9f130dd68ea7cca3d5b20700e808324d84ce583df0cf8b5878038d88761298bc0c7d35386caf5226ea7dfbdb0f157e1dbab026a25c752442566feb3096718ade7ff4ea7458bddeb60ac75b00adcadd8041ccbd6814f83c7b5a42d7dffee4b42f636613e7b31af9e142d2e5a9934e01296d6f8f6db53669b10a40db89137ecc93a5164f147092b0683fae03c0231fee01511cd3afbe61d4efbec769c2cbe21f5399be44ef566d97a2d66b3bcd0b6913ecad715116699abe91f7d9a6afc3d444dbe3640dc0eb694fe7613a21b51b29f6b8148f1ce6383ecc6f386af31775f7eeb830df62f84a9ecb99bf6483de5c5f9c04887f9ee1604e43ca5d5fc1a6a88312a99e17a301adcaa40ee15f8e17ca105387fc7c619e7ee6d827810a3b3f433d631f978a805a9d274640bc
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(129537);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2019-12672");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvg18064");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190925-iosxe-codeexec");
  script_xref(name:"IAVA", value:"2019-A-0352-S");

  script_name(english:"Cisco IOS XE Software Arbitrary Code Execution Vulnerability");
  script_summary(english:"Checks the version of Cisco IOS XE Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a vulnerability.
Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190925-iosxe-codeexec
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a0cbac58");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvg18064");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvg18064");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12672");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(59);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/03");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0); 
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

model = toupper(product_info['model']);

version_list=make_list(
  '3.18.7SP',
  '3.18.6SP',
  '3.18.5SP',
  '3.18.4SP',
  '3.18.4S',
  '3.18.3bSP',
  '3.18.3aSP',
  '3.18.3SP',
  '3.18.3S',
  '3.18.2aSP',
  '3.18.2SP',
  '3.18.2S',
  '3.18.1iSP',
  '3.18.1hSP',
  '3.18.1gSP',
  '3.18.1cSP',
  '3.18.1bSP',
  '3.18.1aSP',
  '3.18.1SP',
  '3.18.1S',
  '3.18.0aS',
  '3.18.0SP',
  '3.18.0S',
  '3.17.4S',
  '3.17.3S',
  '3.17.2S ',
  '3.17.1aS',
  '3.17.1S',
  '3.17.0S',
  '3.16.9S',
  '3.16.8S',
  '3.16.7bS',
  '3.16.7aS',
  '3.16.7S',
  '3.16.6bS',
  '3.16.6S',
  '3.16.5bS',
  '3.16.5aS',
  '3.16.5S',
  '3.16.4gS',
  '3.16.4eS',
  '3.16.4dS',
  '3.16.4cS',
  '3.16.4bS',
  '3.16.4aS',
  '3.16.4S',
  '3.16.3aS',
  '3.16.3S',
  '3.16.2bS',
  '3.16.2aS',
  '3.16.2S',
  '3.16.1aS',
  '3.16.1S',
  '3.16.10S',
  '3.16.0cS',
  '3.16.0bS',
  '3.16.0aS',
  '3.16.0S',
  '3.15.4S',
  '3.15.3S',
  '3.15.2S',
  '3.15.1cS',
  '3.15.1S',
  '3.15.0S',
  '3.14.4S',
  '3.14.3S',
  '3.14.2S',
  '3.14.1S',
  '3.14.0S',
  '3.13.9S',
  '3.13.8S',
  '3.13.7aS',
  '3.13.7S',
  '3.13.6bS',
  '3.13.6aS',
  '3.13.6S',
  '3.13.5aS',
  '3.13.5S',
  '3.13.4S',
  '3.13.3S',
  '3.13.2aS',
  '3.13.2S',
  '3.13.1S',
  '3.13.10S',
  '3.13.0aS',
  '3.13.0S',
  '3.12.4S',
  '3.12.3S',
  '3.12.2S',
  '3.12.1S',
  '3.12.0aS',
  '3.12.0S',
  '3.11.4S',
  '3.11.3S',
  '3.11.2S',
  '3.11.1S',
  '3.11.0S',
  '16.9.3s',
  '16.9.3h',
  '16.9.3a',
  '16.9.3',
  '16.9.2s',
  '16.9.2a',
  '16.9.2',
  '16.9.1s',
  '16.9.1d',
  '16.9.1c',
  '16.9.1b',
  '16.9.1a',
  '16.9.1',
  '16.8.3',
  '16.8.2',
  '16.8.1s',
  '16.8.1e',
  '16.8.1d',
  '16.8.1c',
  '16.8.1b',
  '16.8.1a',
  '16.8.1',
  '16.7.3',
  '16.7.2',
  '16.7.1b',
  '16.7.1a',
  '16.7.1',
  '16.6.7',
  '16.6.6',
  '16.6.5b',
  '16.6.5a',
  '16.6.5',
  '16.6.4s',
  '16.6.4a',
  '16.6.4',
  '16.6.3',
  '16.6.2',
  '16.6.1',
  '16.5.3',
  '16.5.2',
  '16.5.1b',
  '16.5.1a',
  '16.5.1',
  '16.4.3',
  '16.4.2',
  '16.4.1',
  '16.3.9',
  '16.3.8',
  '16.3.7',
  '16.3.6',
  '16.3.5b',
  '16.3.5',
  '16.3.4',
  '16.3.3',
  '16.3.2',
  '16.3.1a',
  '16.3.1',
  '16.2.2',
  '16.2.1',
  '16.1.3',
  '16.1.2',
  '16.1.1'
);

if ('ASR1000' >< model)
{
  workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
  workaround_params = WORKAROUND_CONFIG['rp_check'];
}
else
{
  workarounds = make_list();
  workaround_params = make_list();
}
  

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvg18064'
);

cisco::check_and_report(
  product_info:product_info, 
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting, 
  vuln_versions:version_list
);
