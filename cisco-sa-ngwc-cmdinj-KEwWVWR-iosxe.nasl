#TRUSTED 7764c931218f7e86703870ddfd50be35e420782d063f940a0aec8a869235384f17df14f67ea47da32f0c5c16e330a04db398bc334740c094dd5c9c2378a8652e72e65441e55bb024b571c8de8c8d03cdc3817a3a06e049cd9e93486830ae3a6d865e1de751d090c65bbc37a5c729b800ab7c7bc76bf31001334b5dc9c3d03b3daabe5e9c61c4c492892f1d4eeaf34526e18b8186d8240e37576b7b7055d577fb069fa59fa7bf5bb960165f3400bcb72ec5c851e29e47e51a7d26781f88758be83fae39daf2c16aa6af0673383fca614f0f0542409e4f43ce11d003b7e36821fe5b06fe569cb251474af29f7e38a63d94d273d0ec58fa036bdc378d71e1b92e42732f9489d12f8c8a83c147024f5af2ea724672ca0d0efb9ff353f1f34a7f8694b8c45bfd56d3718e059aa4acfc34f2be6e4f2e322b45a3ead4e890e0df458b8a30edf83f94a6aa1470da275270393adfd406fbc0a0240c3b57b2159ac52e896cfbdbafff00381a7fff071edb94cb0fe92b228ea5b14d90a4e231db0711ac723c07ed06d63a15fedb441d8aae3822a5c6a80133841d598e10e0223826278b69929923b4a50523d274d6b6a27dc246f12dd64021c6b13f5040df922c08054485be6bdbb38f84ce461d317c6d808c4153899cca5888ad6439abd9d6da6bac9af4bbbcb4af888e0298e175fbfc9df1ce83c90bcbbb7f58719b702dace76b958da665
#TRUST-RSA-SHA256 3f8c90bbda23125f454fe470ae4b505d8abbee2b14ba39feb200bd851b657ccbe8b30254772ca10360857c2b186a3757e069542c53236579b23699ac171c90aa35db9c2ffa482d105310cb6f5353aef254910dd4c6cef7af4bb04840655685a6b0fd0c0c2870b0bb9afd96223d1a3329c97fa6fe45c0b2e20d83ce23977457ed467efbcdddae9594435ca19c419a0265e24d682b0980b6979e5514afb03ac4c155f7327c8fb0dcdb83c7da086bf405d06a7ae6b84f950b7411e0608ea8400bebf30bd984aca604b120d44514d9a6c708c4c291cdef5ba5c85721c90f05c888b6189d76a96148c39d71dfdf7d8afda067d32288595194a69bf6a7443b320756586af45238405bc883aba77b1de6e56982f8de0cb1782327412787b057a6ae59bb5852851ae310424c5a356092ef6d7091a762c8c4e4cd38484817c0eb0ce2e4c145efed0b12d5c17dd4a0e03a666f54bedcc3bcf0f0c7cdf29b049bf6dc525afb47a76d91d47f530a7c2e6a7fc346d1d65fc7ec54bbefd5640ba85c78d9009ab7323af12b5d7a0714e60ca30b50506e556308abd408807b9e91997f5e0df605ad2a0e6d9b7a451193404e077461619d8e89e096f3251d269f1f45788c9f5fe6d99bafe1d39ad8514c7d3a84b899882c8d9438a39a3166954acff06875d906ea2210ff2d22db094a264e24c31e6062a6caf141bdf76d70c26ba9efa5734f25ca06
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(137203);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2020-3207");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq90824");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ngwc-cmdinj-KEwWVWR");
  script_xref(name:"IAVA", value:"2020-A-0239-S");

  script_name(english:"Cisco IOS XE Software Command Injection (cisco-sa-ngwc-cmdinj-KEwWVWR)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a command injection vulnerability due 
  to insufficient input validation of boot options. An authenticated, local attacker (with root privileges) can exploit 
  this, by modifying device boot options, to execute arbitrary commands on an affected device. 
  
  Please see the included Cisco BIDs and Cisco Security Advisory for more information.
  
  Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported 
  version");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ngwc-cmdinj-KEwWVWR
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?851db65e");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-73388");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq90824");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvq90824");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3207");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(77);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/08");

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
model = product_info['model'];
device_model = get_kb_item('Host/Cisco/device_model');

if (('catalyst' >!< tolower(model) && 'cat' >!< device_model) || model !~ "3[68]5[0-9]|9[235][0-9]{2}")
  audit(AUDIT_HOST_NOT, 'an affected model');

version_list = make_list(
  '16.9.2',
  '16.9.3',
  '16.9.2a',
  '16.9.2s',
  '16.9.3h',
  '16.9.4',
  '16.9.3s',
  '16.9.3a',
  '16.10.1',
  '16.10.1s',
  '16.10.1e',
  '16.11.1',
  '16.11.1a',
  '16.11.1b',
  '16.11.1s',
  '16.11.1c',
  '16.12.1',
  '16.12.1s',
  '16.12.1c'
);

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvq90824',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
