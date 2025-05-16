#TRUSTED 95882ceb990714c229dc807531599c8aeee951f35cb231e9150b810675b0ff3d197d273b723882ae10bcf5c6ad0cc43537aec6d1322921aa673e34efa1adf0b8e3525311c44545e7c86a478e9436a1ffec08e6fa4c5d3cb9d9b2388aad0d0584fa22624d7e7c049482c12fc8ca34041bd3c56a219e1cae9e48d5cf961e45b84b9854346ebc2a9e6fa4fd88ec8d36f0a23a5e4e18078c1d50bc9f44d331ce095dd16f10b6a9e64e2b70ed9c4fb29367d75b4b248ddbd03b8c0fbf0972425073256ab9dbd43e4e0c3cb5afc43a698406379d024282ad2083db992200b2ce3b21d41dda0c957985c03171a5905e5fd21b2fda3a3c92717e2f548f738d68740b148c68503dea98f6b0b3a7bb914baee11badead212f923a8c1b644a1a4675b21c7f6382695cee98956a3e073bd7e971a98276a81c28a6fdf07198b68968fb473c86fc650c7a7c9852fe88fb0c2b6ad4952d6faceb43eeaea2bc42c0eeacf923d54300b8e9d5d924145e4e39194ca5ed72088af9a2ac0d22f45d1ca9fe0b3cb55ea5b5412f56bd1d725e334aa3ce49872c7b219454a9a67631dab216ecfd99a76c7aed472476e83d2b7479b926c23d6e0f5bd5e07e850b5cc4fd84ac7b309a7b8f1ea728f0e0feb28256665b1f0f8f60956d603fcddf4e1556dd337f3eb0dc01a82b061db5c80f5da0f14d1d05e60bcfa8e7e0cb576e8e4736de927f74831eb5cc6eb
#TRUST-RSA-SHA256 98c94e5d41e52085f392add933fcd41c7daad27e4056e7d94a91070291ce2a623cd68d733356e1cd79563243d3af0a41a2706f11a6f3ac70b79dbd05b2634dd6993e5a0beda18d9a088b3387ae2b51e9fcb0782f7b936248b9cb676ca0ebab902ac6958a6b28d162e356c1cd2f18fa57bdcbb2b5a011f6f2929a60a0ee779e514ef15ef4101770e028bbb9ca42f808969aaf46656497ef15e9f64ef58336509ee7261a770272e3a1861fb8a5c2b2642605024e6adfd0ebe867f8fd05589ae95dd8687a3144b58dc4270a242786379a73a41bbf3aa4bbc4cb48fbf1796693ed6f8a38b94eaffb9f8397e11662361c978f2dc8333c8d76a40689e5ab7cf8a8d0f18a2637dd9ed45b43e46e1532fe8760d6fe835b6c07c1a0aef3ba9553ead5974a53e1e7bdb942fd11ed48d8ce289219e79cc1f0c73b391b036caf3a0bc40ed7743177f776157d571a9475bffa8ff9698bf3e2080055a259a869760ae8cd66afe2c9bbe247800b96119d8ec4a3513fb0bff53f57497baba370538c8eaa6910d121c9d6be6e14ebf9e63c04d0f9cb8ff979f3a2b06beb49eee2daab89393faea6bd755a1c04f7d52b774ccc57f571cffaa96e764e2533d75aa6bbf15986c6866acc915899a03b6f0e1a76f7a1b58cf758d2a7868e3aeb96157840c26804d06f4f7119d2463fbea8c6743cb80d0c18b08b9ef3a466186a066e1f13adaf87411a0fe2
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(129779);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2019-12665");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf36258");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190925-http-client");
  script_xref(name:"IAVA", value:"2019-A-0352-S");

  script_name(english:"Cisco IOS XE Software HTTP Client Information Disclosure Vulnerability (cisco-sa-20190925-http-client)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, IOS XE Software is affected by a vulnerability in the HTTP client feature that
allows an unauthenticated, remote attacker to read and modify data that should normally be sent via an encrypted
channel. This vulnerability is due to TCP port information not being considered when matching new requests to existing,
persistent HTTP connections. An attacker can exploit this vulnerability by acting as a man-in-the-middle and then
reading and/or modifying data that should normally have been set through an encrypted channel.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190925-http-client
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0e0771c9");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvf36258");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvf36258");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12665");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/10");

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

version_list=make_list(
'3.2.0SG',
'3.2.1SG',
'3.2.2SG',
'3.2.3SG',
'3.2.4SG',
'3.2.5SG',
'3.2.6SG',
'3.2.7SG',
'3.2.8SG',
'3.2.9SG',
'3.2.10SG',
'3.2.11SG',
'3.7.0S',
'3.7.1S',
'3.7.2S',
'3.7.3S',
'3.7.4S',
'3.7.5S',
'3.7.6S',
'3.7.7S',
'3.7.8S',
'3.7.4aS',
'3.7.2tS',
'3.7.0bS',
'3.7.1aS',
'3.3.0SG',
'3.3.2SG',
'3.3.1SG',
'3.8.0S',
'3.8.1S',
'3.8.2S',
'3.9.1S',
'3.9.0S',
'3.9.2S',
'3.9.1aS',
'3.9.0aS',
'3.2.0SE',
'3.2.1SE',
'3.2.2SE',
'3.2.3SE',
'3.3.0SE',
'3.3.1SE',
'3.3.2SE',
'3.3.3SE',
'3.3.4SE',
'3.3.5SE',
'3.3.0XO',
'3.3.1XO',
'3.3.2XO',
'3.4.0SG',
'3.4.2SG',
'3.4.1SG',
'3.4.3SG',
'3.4.4SG',
'3.4.5SG',
'3.4.6SG',
'3.4.7SG',
'3.4.8SG',
'3.5.0E',
'3.5.1E',
'3.5.2E',
'3.5.3E',
'3.10.0S',
'3.10.1S',
'3.10.2S',
'3.10.3S',
'3.10.4S',
'3.10.5S',
'3.10.6S',
'3.10.2aS',
'3.10.2tS',
'3.10.7S',
'3.10.8S',
'3.10.8aS',
'3.10.9S',
'3.10.10S',
'3.11.1S',
'3.11.2S',
'3.11.0S',
'3.11.3S',
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
'3.13.0aS',
'3.13.5aS',
'3.13.6S',
'3.13.7S',
'3.13.6aS',
'3.13.6bS',
'3.13.7aS',
'3.13.8S',
'3.13.9S',
'3.13.10S',
'3.6.0E',
'3.6.1E',
'3.6.0aE',
'3.6.0bE',
'3.6.2aE',
'3.6.2E',
'3.6.3E',
'3.6.4E',
'3.6.5E',
'3.6.6E',
'3.6.5aE',
'3.6.5bE',
'3.6.7E',
'3.6.8E',
'3.6.7aE',
'3.6.7bE',
'3.6.9E',
'3.6.9aE',
'3.14.0S',
'3.14.1S',
'3.14.2S',
'3.14.3S',
'3.14.4S',
'3.15.0S',
'3.15.1S',
'3.15.2S',
'3.15.1cS',
'3.15.3S',
'3.15.4S',
'3.3.0SQ',
'3.3.1SQ',
'3.4.0SQ',
'3.4.1SQ',
'3.7.0E',
'3.7.1E',
'3.7.2E',
'3.7.3E',
'3.7.4E',
'3.7.5E',
'3.5.0SQ',
'3.5.1SQ',
'3.5.2SQ',
'3.5.3SQ',
'3.5.4SQ',
'3.5.5SQ',
'3.5.6SQ',
'3.5.7SQ',
'3.5.8SQ',
'3.16.0S',
'3.16.1S',
'3.16.0aS',
'3.16.1aS',
'3.16.2S',
'3.16.2aS',
'3.16.0bS',
'3.16.0cS',
'3.16.3S',
'3.16.2bS',
'3.16.3aS',
'3.16.4S',
'3.16.4aS',
'3.16.4bS',
'3.16.4gS',
'3.16.5S',
'3.16.4cS',
'3.16.4dS',
'3.16.4eS',
'3.16.6S',
'3.16.5aS',
'3.16.5bS',
'3.16.7S',
'3.16.6bS',
'3.16.7aS',
'3.16.7bS',
'3.16.8S',
'3.16.9S',
'3.17.0S',
'3.17.1S',
'3.17.2S',
'3.17.1aS',
'3.17.3S',
'3.17.4S',
'16.1.1',
'16.1.2',
'16.1.3',
'3.2.0JA',
'16.2.1',
'16.2.2',
'3.8.0E',
'3.8.1E',
'3.8.2E',
'3.8.3E',
'3.8.4E',
'3.8.5E',
'3.8.5aE',
'3.8.6E',
'3.8.7E',
'16.3.1',
'16.3.2',
'16.3.3',
'16.3.1a',
'16.3.4',
'16.3.5',
'16.3.5b',
'16.3.6',
'16.3.7',
'16.4.1',
'16.4.2',
'16.4.3',
'16.5.1',
'16.5.1a',
'16.5.1b',
'16.5.2',
'16.5.3',
'3.18.0aS',
'3.18.0S',
'3.18.1S',
'3.18.2S',
'3.18.3S',
'3.18.4S',
'3.18.0SP',
'3.18.1SP',
'3.18.1aSP',
'3.18.1gSP',
'3.18.1bSP',
'3.18.1cSP',
'3.18.2SP',
'3.18.1hSP',
'3.18.2aSP',
'3.18.1iSP',
'3.18.3SP',
'3.18.4SP',
'3.18.3aSP',
'3.18.3bSP',
'3.18.5SP',
'3.18.6SP',
'3.9.0E',
'3.9.1E',
'3.9.2E',
'3.9.2bE',
'16.6.1',
'16.6.2',
'16.6.3',
'16.6.4',
'16.6.4s',
'16.7.1',
'16.7.1a',
'16.7.1b',
'16.7.2',
'16.9.3h',
'3.10.0E',
'3.10.1E',
'3.10.0cE',
'3.10.2E',
'3.10.1aE',
'3.10.1sE'
);

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
'port'     , product_info['port'], 
'severity' , SECURITY_WARNING,
'version'  , product_info['version'],
'bug_id'   , 'CSCvf36258'
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
