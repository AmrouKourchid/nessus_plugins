#TRUSTED 34901bdac9a725190353b21909f11fe205cab4b1576d7d9e6908d573e15bb0bb0d5ff4106516481a1759cdb54c18f74dc4a23e2ad78d1c76a1a011b999f6fced9db02e99bd4c169f44870e3a0b86bc9f844cfbe42d63d03f41a0fee4ae2c1998f3c344282e8fdb684dd25d8ae658bd5a4c7a44e9101a822f9b17408edf688a592c1687b76d2f7e42c63511e13d2f8bb78ec3a77a4e9370f9268e4c74ac27d8189d0432310d68e2563edcb0bb022afff4dcd1578e2ea896f1aa4021621cc20092d2cb8d5bce42776e87d4da4750bc66131524ff1d7c5669650746533ad36fdc87e6aae37133ff6cd2abd920e1e00260c56467ec0959ee00bb2db33c643fd06cdb5aceaba41193c9ac14aa18095515a8815c2a89dc0125a0dfe44e31687dafc950d3080687ce61d5ad53e1f54b1770e34f29ba7c8889d09d431867722205a41797abc944046b86937c12686a7cf7682d95ad7916c0041d9a07f68cd85422e3d3dd3e9e55bc29b4de00caeb12d3df12c4edc15cf2be964dffd9c3c190a179ee3461dde81c5699d37cb3f175fee087645cb1bd8e1dcf890bcb97c9edb4e5658b0e0fa347e2e4a92283739991078e6dd27014aff8142d2814cd8780448e3c3328b42ca4620ce6df7106ca5c0a538d9cfeb2b1f2fdc7562394feb864d1c77a957bee5756ac7cf004aa64f07162a4ec163e9d9c473828ac23cdbabc7e1f7386315e627e
#TRUST-RSA-SHA256 2f0e68bff3835c312ca9e4846549c4dc2a8ff4e0780244603580fa0e76cff0d355aec2fa469514409e2a42b289b848cfd16c0b25c6126c951a0ffbb562132296c44b54da25211c7715e2ab7395a14f894f16af206467b43bc332754d6d2aaf116053ce37bd6510ad2cb014bd970d1cc7fc156e652567e1838790101d27330674a735ea1ba215a7bf2b154a32a3abdd72513ce9263151e079bd2bc1b667d712f7b7df54788c078ddaa0de1c272fea20f4359f5a63281f8f223ae83d0be89e16cf85cdda0cdbc410c09086d2593536fe1defa309461156c6db8f9af95918aee1b59fb99f2560f53d3cb35627ddee4616aa2b87e07a6dfd92b684d5cdb7691df04f9f8339514b34e1d4665521067de8289745ac467028d1e5051ca7398762083532c488fd70dcf494343bc1dd2061cc5885de116767c8a4f52f0d7372af8b7e6012c8f6766f70fdfb128e781d0644c022d7c42411193a8233475afd34ee4520e0d7588fadc853902b21205ad8818097ff18e1ba11b70b13deb7b679c64853543759cbcfd8b358d7caed95cffa7c5e41573b38713bfb998c51cec54169154dd571abd7fe559c3ad9821ad263132ae91fafb1970490db4e84578c81328f83d7be51bfa0e23971ed24789a7cec152164f0ccb04dd99ad1a0293929679c24ed795a59cf16cda6e8cfc1556aee8b9ff0ecb9901bf57503c33e16689194d2a48329fec444
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(132041);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2018-15374");
  script_bugtraq_id(105415);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvh15737");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180926-digsig");

  script_name(english:"Cisco IOS XE Software Digital Signature Verification Bypass (cisco-sa-20180926-digsig)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a digital signature verification bypass
vulnerability in the Image Verification feature. An authenticated, local attacker can exploit this, by uploading a
malicious software image or file to an affected device, in order to bypass digital signature verification checks for
software images and files to install a malicious software image or file.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180926-digsig
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5094f8e6");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvh15737");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s) CSCvh15737.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-15374");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/13");

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
  '16.1.1',
  '16.1.2',
  '16.1.3',
  '16.2.1',
  '16.2.2',
  '16.3.1',
  '16.3.2',
  '16.3.3',
  '16.3.1a',
  '16.3.4',
  '16.3.5',
  '16.3.5b',
  '16.4.1',
  '16.4.2',
  '16.4.3',
  '16.5.1',
  '16.5.1a',
  '16.5.1b',
  '16.5.2',
  '16.6.1',
  '16.6.2',
  '16.6.3',
  '16.7.1',
  '16.7.1a',
  '16.7.1b',
  '16.9.1b'
);

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvh15737'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
