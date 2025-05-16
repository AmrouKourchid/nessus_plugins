#TRUSTED 81c3a8e79a9c691d0cf0032d40a95eb0aaccf84e02f4d084dac70c849c570b9b01e2555df437081d724d5aea7086ccf232388ed0e80b84fe2996436982f8e8c7e7b87a08c27443c9b9f5d668985ec2e039494eea14f5b37902b48c1f13d6002684ed6770721f3799f76b9a32e14b3b584076ced22f4ad6d2aa232e4c4afd9cf17f4b5e6a5cd0f56cd7a8b8f14f72e21ca17c0c4ebb99348e54f4b62c0a0cfafa7742d97a4df6f2220e1c3e878f41db1626ba84fb026a773f1a26ba44d81e5cdaff3fcc7bda4f33a8248828988b8a22853d88f5c8fb6cc4bb067813b3d5ec82cf5deb079adc730f80a682ac2031c984aad7694ea1828c5f45b4c66c8f92e44b75abea421a8a0afd6c4f190d592569eeb4a22d4092c4b1128a26102269c4622dc9388ac724e7950545426649d49c38f25913ddaf131d3a172b12cf674893089c9bf162535b5d2d84e47048bf8ececdf3125670ee697092f9b77a36c2115b4c67df69ad2d503b4be2c5fbf00ea87db1f7596606907a90bf2e2c0566f5d35823a83db6f0323cc60ec7631ac49faecf53a2271c7722cc6ea0cd731f6a2139a5397734d7801ccf45bbe39c951852b00173fd9b230ec1588b89e2e7ef03f3432113c4a7f4a8aad3eb2fc23d2ae4a838e5b047e7f155a59482950bf724a5a10c4f7a2b9b08009d10b2770951f2f5dcc5dcd97ab8414e175f1ece625554fac6e831f477a9
#TRUST-RSA-SHA256 0af32d2ced3ce76731757bbf0fe63b8cd55d324cf5f9ef3702a0c4dd52170523b43c1155d52f93c5408ea87c21b6433c45e80633ad22d6cac7934fb963ef76d7bc42aae7b881c14e9d096eac7877268b890b564c1692f0bc074dabce02d57b803214d8158c4dc47a458683c80e722069aa43990e4c1b294c869169731e83e801a79ecc1420d027a59120089a686dea7adc179807225c76b35f5c56b6ba49a3c0653950b471d401674518a67b72142bcbc91c4c425a0905d0f9c6f632acf232a912c850d235e98fd8848238a58bf51141f012f79ff2eaaa9a0a15fe09e82bc4cb096a17432fd5bc36f827246cd26cab06c90a4153223d13017486e1f58810d288e734cf6e9d39e8f3164ad43b80b230a8e3a79028f6aa6d327d80de31ad67a04520e063d568f0a7465a3be39984206ae9b2ed3907286d9d02a207aa7491eebeba256970aead9080e4fdc5b9ab5fa77a510fc7c6464422281870310f1e71f76ee4456f17972e80307a450d8c2b446d0bebdf0e8ff8d659d953452a18171c1b967941be5aeda9b787f3332bb4219215c264556c1510b4b27ca2d8e27b07d77ba17610ab70c7a20690453ac953a81d9e7def7009c07582c496cc374ef555ba5ca709e682f363bc60c00465ef66c68976a3ebff713673d8e8a96ed35f280fdd8d3e15515d8ffca2dcc8624c1d70f7285ec68802a92f0b02c1f97405e0c6a09b669235
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(131080);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2017-6665");
  script_bugtraq_id(99969);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvd51214");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170726-aniacp");

  script_name(english:"Cisco IOS XE Software Autonomic Control Plane Channel Information Disclosure (cisco-sa-20170726-aniacp)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by an information disclosure vulnerability in
the Autonomic Networking feature due to unknown reasons. An unauthenticated, adjacent attacker can exploit this by
capturing and replaying Autonomic Control Plane (ACP) packets that are transferred within an affected system in order
to reset the ACP of an affected system and cause the system to stop responding. An attacker can also view the ACP
packets which should have been encrypted over the ACP, in clear text.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170726-aniacp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f352f2d4");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvd51214");
  script_set_attribute(attribute:"solution", value:
"No fixes are available. For more information, see Cisco bug ID(s) CSCvd51214.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-6665");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/18");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list = make_list(
  '3.10.4S',
  '3.10.1xcS',
  '3.10.8aS',
  '3.11.4S',
  '3.12.0S',
  '3.12.1S',
  '3.12.2S',
  '3.12.3S',
  '3.12.0aS',
  '3.12.4S',
  '3.13.0S',
  '3.13.1S',
  '3.13.2S',
  '3.13.3S',
  '3.13.4S',
  '3.13.5S',
  '3.13.2aS',
  '3.13.6S',
  '3.13.6aS',
  '3.13.7aS',
  '3.13.8S',
  '3.14.0S',
  '3.14.1S',
  '3.14.2S',
  '3.14.3S',
  '3.14.4S',
  '3.15.0S',
  '3.15.1S',
  '3.15.2S',
  '3.15.1xbS',
  '3.15.2xbS',
  '3.15.3S',
  '3.15.4S',
  '3.7.0E',
  '3.7.1E',
  '3.7.2E',
  '3.7.3E',
  '3.7.4E',
  '3.7.5E',
  '3.16.0S',
  '3.16.1S',
  '3.16.0aS',
  '3.16.1aS',
  '3.16.2S',
  '3.16.2aS',
  '3.16.0bS',
  '3.16.3S',
  '3.16.3aS',
  '3.16.4S',
  '3.16.4aS',
  '3.16.4bS',
  '3.16.5S',
  '3.16.4cS',
  '3.16.6S',
  '3.16.5aS',
  '3.16.5bS',
  '3.16.7S',
  '3.16.6bS',
  '3.16.7aS',
  '3.16.7bS',
  '3.16.8S',
  '3.16.9S',
  '3.16.10S',
  '3.17.0S',
  '3.17.1S',
  '3.17.2S',
  '3.17.3S',
  '3.17.4S',
  '16.1.2',
  '16.1.3',
  '16.2.1',
  '16.2.2',
  '3.8.0E',
  '3.8.1E',
  '3.8.2E',
  '3.8.3E',
  '16.3.1',
  '16.3.2',
  '16.3.3',
  '16.3.1a',
  '16.3.4',
  '16.3.5',
  '16.3.5b',
  '16.3.6',
  '16.3.7',
  '16.3.8',
  '16.3.9',
  '16.4.1',
  '16.4.2',
  '16.4.3',
  '16.5.1',
  '16.5.1a',
  '16.5.1b',
  '16.5.2',
  '16.5.3',
  '3.18.0S',
  '3.18.1S',
  '3.18.2S',
  '3.18.3S',
  '3.18.4S',
  '3.18.0SP',
  '3.18.1SP',
  '3.18.1gSP',
  '3.18.1bSP',
  '3.18.1cSP',
  '3.18.2SP',
  '3.18.1hSP',
  '3.18.1iSP',
  '3.18.3SP',
  '3.18.4SP',
  '3.18.3bSP',
  '3.18.5SP',
  '3.18.7SP',
  '3.18.8SP',
  '3.9.0E',
  '3.9.1E',
  '16.6.1',
  '16.6.2',
  '16.6.3',
  '16.6.4',
  '16.6.5',
  '16.6.4a',
  '16.6.5a',
  '16.6.6',
  '16.6.5b',
  '16.6.7',
  '16.6.7a',
  '16.7.1',
  '16.7.2',
  '16.7.3',
  '16.8.1',
  '16.8.1a',
  '16.8.1b',
  '16.8.1s',
  '16.8.1c',
  '16.8.2',
  '16.8.3',
  '16.9.1',
  '16.9.1a',
  '16.9.1s',
  '16.9.3',
  '16.9.2a',
  '16.9.2s',
  '16.9.3h',
  '16.9.4',
  '16.9.3s',
  '16.9.3a',
  '16.9.4c',
  '16.10.1',
  '16.10.1a',
  '16.10.1b',
  '16.10.1s',
  '16.10.1e',
  '16.10.2',
  '16.11.1',
  '16.11.1a',
  '16.11.1b',
  '16.11.2',
  '16.11.1s',
  '16.11.1c',
  '16.12.1',
  '16.12.1s',
  '16.12.1a',
  '16.12.1c',
  '16.12.2',
  '17.2.1'
);

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['autonomic_networking'];

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_NOTE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvd51214',
  'cmds'     , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list,
  workarounds:workarounds,
  workaround_params:workaround_params
);
