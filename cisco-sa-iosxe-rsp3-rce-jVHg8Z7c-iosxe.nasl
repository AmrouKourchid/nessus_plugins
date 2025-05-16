#TRUSTED 9e573861811465b858af97ff3de7cf36a86a2ec1cfa810b87769850d779154a5a30f622e13cfa8b3d25ae69b2d37ca9632e439df2601b15cfd6ba45c028d7648a73ad0d20b736c32e61f114ef8d958dc5506fb955cdae8fbf514a3cd2577027ef56b37d91374f0a8efff28ff681f4dac16a4fd925b308b73ce2c3a84ee3ac41b51b9bb5abf7562b4aa4d0834a22a6e8bd7c30b2c868fde58a936bde10b3f8560deb0a836cc7964731927abfbca1cbc4d54000e2fa7379240a0b6ece2adceb72364d838e1870d5a94199d125d7cc529cd860df47cae752da15fa3e4307be59c13d0cb04ff38fb5719a75e094a53bfc2c8ca063041431cb763fbedf0cf1f979b385722af89d458ba884c8e7dc1a9be156210afecd517b1f3ac9e938990b2aa2e0a82f776c72b29c1b5ba5494ac70e610a56aca49fa5dfdb24bdbe8b0294596c51ed973358b85db96bbd4b02bad5876f02fe540069446faaabb207f767e8aaa0a8f36702745fb8a8bfa6c9277dc8b1101887acc7d2963625795ef4b71372b72d227499b864e185feb7ee4d370e0820c9e828c22f1cd6dd3ab7c77e084bef95d480a914d9833bdbcd2ae97e8c418b8dbb88a3e4e46ae5e622a6566c78b3df90d408ad55767a18c80c7205c215dd3bd6efe932c4f1eb0d52908ef3d39e0880177854dd3c2ad6e37faaa273ba0abd4bcefe326a39785adbd670997a28ea0fa9c258d81
#TRUST-RSA-SHA256 ab306dcc5911b370a2e10d7865a31159ff318a6f0aa0f23707ee9fbf550d1f2be0183112faea10db687255633744ea72f47d145682640433b0e0e09a0fdd74841f4e891585b1e5b611299effff0d94e6bb428c13cdf375cc6b91150e06bb9a4e9d3ef448449d37d8ab65a7ed1d1f25372c6521e4c0b74330fb8db8cf82fe90fef9bf3ce93f36220a558eb04faf5d32a6eb8eb6c6aeb5dfac83e582fc7b9432f8895bd283185270cf9c4655c68b491b0138e8ef2f68faf2894b1e3cb8e305ff4abc8059a05a0d5875979b1d75e2e27856083079a2a4d6e97452de8885174ec841a54fdd9a02edadf85db465743548b7db7375cf171b18c6ec8b2bea38a3448b0acf0521e35f553c9fb2d7856550c7e3ca7af48e2f9316f98c0fa6901cb826cd2ddc90b5808fe41f89481d69c49d977d13a9300e7bd02f193ac4b1989f499bedb742f995dfb3f40f60effef267df10b995f1c3b008d4243929991164cbc9af585623ac5ccc98eb681922bbfb9e69ab0774bbe2a411dc7d7f351e5a96383e53edcddf2a826605386de19ecc483e9236ce7872331433f791475d3615d46437d231f39052785ac435c23e167eb5a6a1c6fb4537544a3908a0c7704bb9ca6ca17f76cdd2e8adff725c9fb5386512f23bed212c434cae03088b6db9bc906767ff1998004a17f02cae13f8cf93c79151d82eb1b4ac1c11a93f6e45761ccb5081dca2a9ef
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(141371);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2020-3416", "CVE-2020-3513");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr69196");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs62410");
  script_xref(name:"CISCO-SA", value:"cisco-sa-iosxe-rsp3-rce-jVHg8Z7c");
  script_xref(name:"IAVA", value:"2020-A-0439-S");

  script_name(english:"Cisco IOS XE Software for ASR 900 Series Route Switch Processor 3 Arbitrary Code Execution (cisco-sa-iosxe-rsp3-rce-jVHg8Z7c)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, IOS-XE for Cisco ASR 900 Series Aggregation Services Routers is affected by
multiple vulnerabilities due to incorrect validations by boot scripts when specific ROM monitor (ROMMON) variables
are set.  

An authenticated, local attacker with high privileges to execute persistent code at bootup could exploit this by
copying a specific file to the local file system of an affected device and defining specific ROMMON variables. A
successful exploit could allow the attacker to run arbitrary code on the underlying operating system (OS) with root
privileges. To exploit these vulnerabilities, an attacker would need to have access to the root shell on the device
or have physical access to the device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-rsp3-rce-jVHg8Z7c
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7666b559");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74268");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr69196");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs62410");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvr69196, CSCvs62410");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3513");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(749);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/12");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/IOS-XE/Model");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

model = toupper(product_info['model']);
if (model !~ 'ASR90[0-9]([^0-9]|$)')
  audit(AUDIT_HOST_NOT, 'an affected model');

vuln_versions = make_list(
  '16.10.1',
  '16.11.1',
  '16.11.1a',
  '16.11.2',
  '16.12.1',
  '16.12.2',
  '16.12.2a',
  '16.12.3',
  '16.12.3s',
  '16.2.1',
  '16.2.2',
  '16.3.1',
  '16.3.10',
  '16.3.1a',
  '16.3.2',
  '16.3.3',
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
  '16.6.1',
  '16.6.2',
  '16.6.3',
  '16.6.4',
  '16.6.5',
  '16.6.5a',
  '16.6.6',
  '16.6.7',
  '16.6.8',
  '16.7.1',
  '16.7.2',
  '16.7.3',
  '16.8.1',
  '16.8.1b',
  '16.8.1c',
  '16.9.1',
  '16.9.1a',
  '16.9.1b',
  '16.9.2',
  '16.9.3',
  '16.9.3h',
  '16.9.4',
  '16.9.5',
  '16.9.5f',
  '17.1.1',
  '17.1.1a',
  '3.16.0S',
  '3.16.0aS',
  '3.16.0bS',
  '3.16.0cS',
  '3.16.10S',
  '3.16.1S',
  '3.16.1aS',
  '3.16.2aS',
  '3.16.2bS',
  '3.16.3S',
  '3.16.3aS',
  '3.16.4S',
  '3.16.4aS',
  '3.16.4bS',
  '3.16.4cS',
  '3.16.4dS',
  '3.16.4eS',
  '3.16.4gS',
  '3.16.5S',
  '3.16.5aS',
  '3.16.5bS',
  '3.16.6S',
  '3.16.6bS',
  '3.16.7S',
  '3.16.7aS',
  '3.16.7bS',
  '3.16.8S',
  '3.16.9S',
  '3.17.0S',
  '3.17.1S',
  '3.17.1aS',
  '3.17.2S',
  '3.17.3S',
  '3.17.4S',
  '3.18.0S',
  '3.18.0SP',
  '3.18.0aS',
  '3.18.1S',
  '3.18.1SP',
  '3.18.1bSP',
  '3.18.1gSP',
  '3.18.1hSP',
  '3.18.1iSP',
  '3.18.2S',
  '3.18.2SP',
  '3.18.3S',
  '3.18.3SP',
  '3.18.4S',
  '3.18.4SP',
  '3.18.5SP',
  '3.18.6SP',
  '3.18.7SP',
  '3.18.8SP',
  '3.18.8aSP'
);

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvr69196, CSCvs62410',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:vuln_versions
);
