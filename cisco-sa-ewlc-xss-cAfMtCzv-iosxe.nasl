#TRUSTED 03dfbf97dff6b4363b287e1fb9643de3dbed3b4540227f2c3d9ed83091b9c644623a9ec83c423e9417a6250c19b810acbc7f5720aec3168f6f40e71137388f478eacb2cbb96437ef94b5bb2d39b4c832773e02bddcc0579b783d830f965edb9718ca9a5bb6bea02b9ceeab4e2118a4c2b382fc247beafc520e47312e2140f7359316458328990f073f28c95df4cd9827226c01834891c2092659185345c8a2323779a0f76b9e9782490713bfb32956eea5705f1c8584067067240db6bfad0739863426bcaf9c30f78c0c300bdf3508e315d90f1e4446c890fa40569c9041cc65bd02a852eec6c379b55e0e2f52454a6c2ad0db3b5d9d6ca4a9a69883ac447f8c0f006c38ffa0acafc28f1638b190baa09cd4e13c70e0394552d1144d422edee7908cd36c91279c403e5bb91cf966da45d4ae3c3f11b8bb11e4f95b92c1d2d40b58b31d58f22b02648231b682151d48bd2917d09b765510ca24efc60879c1f53707f3a91b1fdeed6c7e7b49f78b818dd3a670faab35a1d3d16d5ee0c074323e67f761cca56662e9288776ea14d2d0bcb9129f62800b9183663707fc9e5ae1835e74e56821a2873e438215c72a28d6a1017ff540e321f595486f319187680e51ede69f8f17fe7856f44254cab0cd5b4e9accd6cc9950f1034d5cfb14d1705ed357bbedb28f79bf0f983b9bfd3130b79dbf3e9773fcc6f8ef2445a05b2224a251cf
#TRUST-RSA-SHA256 549756d1e248fb5eaef30f8af1836c02d462d1c9ed6f1c5f8718b59d15a945db304d4d04939e0fcfec8db650695fc158d0fac14480572cb96ea208b054d5d96fff7cd050cd8c4a92e4bf08a7001cf6c8e212befebef8d5620ecfd5218476fa7859021a56a8702cdfd7f4c02a6046cdca02e1b6c748edeb12445faf5662cd310cd7569a534e094c4c11a7352bb8eea7bcb3b3eedc6864b5d98ac3daf70905c15e7d6e87a3a482a947d3b6bd5e85e8b17d5bc0f5b42e2da3eca47896c1fc87de15c964c9c9b546d8c3f75d51c9afe56c53a43c2987644c18b358b7e01d8d4246acfd4bc1ea685338c07593677a0bd2aca60bebd525d59d42d28d3f31f68d159343c9a0673c460e3d1fd2f45d2acc92ab836a59bdc27018e303b83ea90c838d7fb3e990b14c44e5e329730720f8eec5de478258a424ad74e2982ed12e991419d5b7f24e7eab4477bef06f7d2c79e3be6945a3fa138a979f9e34e250d05ec68302874f4553aad3c415a93d549ff1f46f55e62d92190f96c8025623c65a164549d178d8e1e48615b05c6267199f45050149032c4b8f717513b5f15292b4e87d2efbb93a6493ee2bc29d25b54ea9d69ed8850af243795482f9f49e5e80a88779124c287d07051bb893adac9e1b14792688ffbc8026d6fbacb7ccaac8c59dc8e0ec24d0cef4e3dd54453dee43f84593e2196975dc6ac4ac1977b7c3aa657c461f6b934b
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148092);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2021-1374");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv02020");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ewlc-xss-cAfMtCzv");

  script_name(english:"Cisco IOS XE Software Wireless Controller for the Catalyst 9000 Family Stored Cross Site Scripting (cisco-sa-ewlc-xss-cAfMtCzv)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS-XE Software is affected by a vulnerability. Please see the included
Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ewlc-xss-cAfMtCzv
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?904a8176");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv02020");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvv02020");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1374");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/24");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/IOS-XE/Model");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

model = toupper(product_info.model);
    
# Vulnerable model list
if ((model !~ 'cat' || (model !~ '9300')) &&
    (model !~ 'cat' || (model !~ '9400')) &&
    (model !~ 'cat' || (model !~ '9500')) &&
    (model !~ 'cat' || (model !~ '9800')))
    audit(AUDIT_DEVICE_NOT_VULN, model);

version_list=make_list(
  '16.6.1',
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
  '16.12.1z',
  '16.12.2',
  '16.12.2a',
  '16.12.2s',
  '16.12.2t',
  '16.12.3',
  '16.12.3a',
  '16.12.3s',
  '16.12.4',
  '16.12.4a',
  '17.1.1',
  '17.1.1a',
  '17.1.1s',
  '17.1.1t',
  '17.1.2',
  '17.2.1',
  '17.2.1a',
  '17.2.1r',
  '17.2.1v'
);

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_NOTE,
  'bug_id'   , 'CSCvv02020',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
