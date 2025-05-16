#TRUSTED 9eb3f75fc2908223b97c42cd2ac2410965573a72f1ece6438f86f17bf6a208bfb710f86ecaef0a85f0e3ab7a6701f7de82fc0561a960dcf95a2a9e5dd934cfb5a852920156899f4f497e28e454d4acc37f020ec5467b980fd35405f0767204f8b6981df15521bbdb59ae2009a1776ee5affd587fcfbeeb3a951f0ea8d28b61a824bfa0375d060fcc55f8f33886b34935f3d3f2cdd864b3563917f4fe2f89844cd5d5a3b4128e584d33195afe9aad026185a1b7ba6f0b1c6a19377d64fb9c681b6af0d693b292d34786713ea6cc31875c4d6db902af1057b8eb8c944460907e5f9d5d5d58b7a3c5d7c8a0fc5c69d98f61ce42b38124884410be2d34da99d90b8839731a7abf4ed6f32dc289faf870aa2e6f4b8faa659fbbfe47c40eab24bb3278f40cc07313d773b7e8472a829d6b9f3bfb9f9f9fe340e279b9493304530885fe393de10837e9528aa4d411b4b26bf59db1ad4f1fc62e3719eac0ed9221a7f8080514ccf63c2877ce98904f85be784285b9581b9aa0be826544d35c62efe08890150a55a05879a7590f58dea2cc4ba9ed5851f4f2daa09928c73bc66850e10ee2a424be4942fab29d86f6c27261688688d0546f3b18fd3d0b5fd4979a4f9e35a642cc0e0e47a1419fdaeef4b5c39dc1e056adc6fb93d048226002353fa681c004900f4876a862ff171f750da287ff55348e6bb5d4ee1a2effb595586650a36ce4
#TRUST-RSA-SHA256 835090617804f1b99aac1fa33041a994bb0fb00b1b6db6169263cb2b2909cb9c8afb233e6de9dd12c1d44d18df44f6cadddcfe72463131b56c94b0b22525cfa9f161953ac4bcd5e4f7c5f4a2692d1aa06222867ba885d2c20ba3757a7a5d84f889c74706111cdffa48cfb392d375bad7e15f76d5104a7f018cb617601a745ec4c6ea2822271e2c14ec7cffb58a5037c1848b3f017ac1c73a1ec435ed46b6c9eff481e772aab8429e1dde97e551794787d2022021f23faf77f9497897789a376abf452b71279dcad1d9795755487f4db36414eb5fd6285b9de8e38c60dc21d7a63bbf4324eabdb21eacc730896432f53f07a397951b0bde3eb6de748c335532ee05b16d050891de33133bfee03c8a87ae607816a78bb38ca3148504cbf770eff0a8b83238acec1c9cf125e192d8fbff49edd0688694a2cc126b55084d23b52d0eb3d92aeb1d25851ea856f6f84647bf6d42fc4fdbc7c0f19986e9d41adb355f8782050a9f3afb5b27cbc1a2c72ec92db52e9307020fe932bae1fcfd32ea62138356c98e2a0873df122ff9b30ccab51a85a400bb8bdec587f116be9b6104baa8fea59f58e4a7a9e33f58ef0a67f64832a11a417458e4d1e6a0e7a04bc061c896672f1572e9e5f833315fde3cd3088ec18cbe82cce253694dd621e723d3f798c98100a24a060863c2b5014608b0132b052590bf9d7899f2398239b0964ab961327f
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(141437);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2020-3465");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu30597");
  script_xref(name:"CISCO-SA", value:"cisco-sa-le-drTOB625");
  script_xref(name:"IAVA", value:"2020-A-0439-S");

  script_name(english:"Cisco IOS XE & Cisco IOS XE SDWAN Ethernet Frame DoS (cisco-sa-le-drTOB625)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE or Cisco IOS XE SDWAN is affected by a denial of service (DoS) 
vulnerability in its networking component due to a failure to handle malformed ethernet frames. An unauthenticated, 
adjacent attacker can exploit this issue, by sending specially crafted ethernet frames to an affected device, to force 
a reload of the device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported 
version");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-le-drTOB625
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?218a376f");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74268");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu30597");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvu30597");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3465");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/14");

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

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');
model = toupper(product_info['model']);
if(!pgrep(pattern:"C9800-C?L|ISR((10|43)[0-9]{2}|4221|V)|IR11[0-9]{2}|CSR10[0-9]{2}V|ESR63[0-9]{2}|VG400", string:model))
  audit(AUDIT_HOST_NOT, 'an affected model');

version_list = make_list(
  '16.8.1',
  '16.8.1a',
  '16.8.1b',
  '16.8.1s',
  '16.8.1c',
  '16.8.1d',
  '16.8.2',
  '16.8.1e',
  '16.8.3',
  '16.9.1',
  '16.9.2',
  '16.9.1a',
  '16.9.1b',
  '16.9.1s',
  '16.9.1c',
  '16.9.1d',
  '16.9.3',
  '16.9.2a',
  '16.9.2s',
  '16.9.3h',
  '16.9.4',
  '16.9.3s',
  '16.9.3a',
  '16.9.4c',
  '16.9.5',
  '16.9.5f',
  '16.10.1',
  '16.10.1a',
  '16.10.1b',
  '16.10.1s',
  '16.10.1c',
  '16.10.1e',
  '16.10.1d',
  '16.10.2',
  '16.10.1f',
  '16.10.1g',
  '16.10.3',
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
  '16.12.1w',
  '16.12.2',
  '16.12.1y',
  '16.12.2a',
  '16.12.3',
  '16.12.2s',
  '16.12.1x',
  '16.12.1t',
  '16.12.2t',
  '16.12.3s',
  '16.12.1z',
  '16.12.3a',
  '17.1.1',
  '17.1.1a',
  '17.1.1s',
  '17.1.2',
  '17.1.1t',
  '17.2.1',
  '17.2.1r',
  '17.2.1a',
  '17.2.1t',
  '17.2.1v'
);

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvu30597',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
