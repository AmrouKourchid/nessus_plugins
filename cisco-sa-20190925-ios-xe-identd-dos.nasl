#TRUSTED 0209d21826d5366889cf777653fe35a757cdd88f4f60b04d8e40614b30a15c5fd49f6e105ffd78d7662ed368b6f0c91cfbeb48066b6a6d9f3f76d9bbc07186d5dc9a953a04830e71b7766805ae54f54d5a3cba71e56d735b40d6ff9b24bedf7c328b4c436dc0d5c931e7a0cfc807315cbc3328741b7cc09d0af091389a4a8dcbe31f5fdbc03fd2a02ece8f8f9d4cd4193983a9d17e4ae24e6cb11f846dd5dc19c636d4162c0a820d2190e941dc660f9e1a93ca08d91802f0c311bc4588fd6be720ee6829fee5a4812a6299469bd1bb1ba99124bba42b95439820718526eac0529b19583d6eed790467548ad68b3cc44de1ff12e17981f6e6cc9b852feb0191cf6ffa5824cf41404788c1380e55763af96674fe6c23280d108578547beced4c952e3ecd72ca89f12afbff04c64575ce134b1631697c845c8de3f1918289cda3b831d12cd7faa6c7faaf9a43360dab80462af3b8ae0cf4406f3276dd3445cdebcaebe810b57581cd5be0775b1b11cb857e41b5480bfb05dda1a73fb554a0b86c1c886a9a30092df3cddf39ec56a8b3a2b44d4c491f42b5136dbd1863c3541857336ee276cf57f80aafc751d50049a153d1f6508cae7c6f7e8143e93809817b143ae09a68a24011807320006da3471355ec3a716cd6705c7ee5e8876e4175d41c490129727cb7442bf8777bdfdc9144f7610dde4b16589584f1852fff5ee1473e0b
#TRUST-RSA-SHA256 3863545a5f6033189a70313db751e8e9b48c2a3fdb2121d325a5d1419aca0d2aafb068666877adaafb9d17ebcb8e324898738eafcb285206ae5832080aed2c7ffa09fae6536b420ee45c523b74a48741e4347442a69da86eb4d26076676cb773b94b233941f8c5f77d2e996298654d654b07194e0de6cc44f9e6bc26e399efe1666ed0d16f9c896a18f133c47db89e7d9ba1c70b13f4e3959ef6e312c1053f39a3b5349f367e14d84f89397578a5baff0b5baf84e39bab0b25f8f60f7cf7f759bb6042e3add99c39b8eb199fc8faaf2159ae386a6505c2516383dfb4424bc65fac78ca8467fa660022d5d8fad66db6202be4aabc4ba9aed16c9456dd4cd8f82476f38a271c713e4df80aba7e5c1028377bc1f658c47505c6db8ec4517462fa332daa55ab115cc7d0c6e74537d08ecfab186adc98a68ac767f1af519ffad550c49d4529986a1e0559de8035fc4f40880dea35d6d82095050ec87705fa4861f42a4bf36892d42fdb53634ef4d05a5cb8a007d7f059f3762a67d83f6ac75294b9f46a7f837625de0258e859e820287d89746941d3c24220266e43ed365907828093d400c7d0e5e73106915895bfc070f5d8baa48f387db2745f7bce1a6070338cfab9ae5cd8d761a74ef63e482e30ed5017180fab2c7085550202ec1f94dff04458315d4b95f801d2e32ef5c3ee8345d9a40e78f1e0fe77bf3748b9e8392b00b8c1
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(130022);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2019-12647");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvm01689");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190417-ios-xr-dos");
  script_xref(name:"IAVA", value:"2019-A-0354-S");

  script_name(english:"Cisco IOS XR gRPC Software Denial of Service Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is
affected by a denial of service (DoS) vulnerability exists in Ident protocol
handler of Cisco IOS and IOS XE Software due to incorrectly handling memory 
structures, leading to a NULL pointer dereference. An unauthenticated,
remote attacker can exploit this issue, via opening a TCP connection to
specific ports and sending traffic over that connection, to cause the
affected device to reload, resulting in a denial of service (DoS)
condition. 

Please see the included Cisco BIDs and Cisco Security Advisory for
more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190925-identd-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?09b027b1");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvm01689");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvm01689");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12647");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(476);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/18");

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

version_list = make_list(
	'3.2.11aSG',
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
	'3.8.0S',
	'3.8.1S',
	'3.8.2S',
	'3.9.1S',
	'3.9.0S',
	'3.9.2S',
	'3.9.0aS',
	'3.3.0XO',
	'3.3.1XO',
	'3.3.2XO',
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
	'3.6.5bE',
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
	'3.16.0S',
	'3.16.1S',
	'3.16.1aS',
	'3.16.2S',
	'3.16.0cS',
	'3.16.3S',
	'3.16.2bS',
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
	'3.17.2S ',
	'3.17.1aS',
	'3.17.3S',
	'3.17.4S',
	'16.2.1',
	'16.2.2',
	'16.3.1',
	'16.3.2',
	'16.3.3',
	'16.3.1a',
	'16.3.4',
	'16.3.5',
	'16.3.6',
	'16.3.7',
	'16.3.8',
	'16.4.1',
	'16.4.2',
	'16.4.3',
	'16.5.1',
	'16.5.1b',
	'16.5.2',
	'16.5.3',
	'3.18.0aS',
	'3.18.1SP',
	'3.18.1aSP',
	'3.18.2aSP',
	'3.18.3SP',
	'3.18.4SP',
	'3.18.3aSP',
	'3.18.3bSP',
	'3.18.5SP',
	'3.18.6SP',
	'16.6.1',
	'16.6.2',
	'16.6.3',
	'16.6.4',
	'16.6.4s',
	'16.7.1',
	'16.7.1a',
	'16.7.1b',
	'16.7.2',
	'16.7.3',
	'16.7.4',
	'16.8.1',
	'16.8.1a',
	'16.8.1s',
	'16.8.1c',
	'16.8.1d',
	'16.8.2',
	'16.8.1e',
	'16.8.3',
	'16.9.1',
	'16.9.1a',
	'16.9.1s',
	'16.9.1c',
	'17.2.1',
	'17.3.1',
	'17.4.1',
	'17.5.1',
	'17.6.1'
);

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['ip_identd'];

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvm01689',
  'cmds'     , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);

