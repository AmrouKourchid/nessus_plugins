#TRUSTED 20084daaaa3b31439d79cdee2d192464aad6da7ad39bc2bdc6beb48a63830de19099f6d280245d135a2f544853f09be7d5f2727ce1592f11e6d5fdfc72aa63d52c4e4176442234539ad9167a121b0b4490ea66f7f2d49ccde25fd96a6e2d200f3a05a331c1150c73233eede86b1b5870c099bbb1a764cb20a5074b9100c6469f699da7880f56722a9449c7a12e4380759f5b3ff1bdc52193a4be70fb944a707ea410c97145a7b8d06a8eafb814a56280e1f7e1213833359e6272b138128ff91bf2f8e7da9f6aa0a5acf042e7b179720cd13e7d4b3fc1bae2b3c3c4e7f375d18ce37e26c1b944112aa14347384e19de28f1c252e7a1d8f77bb48b38346f30b3beddc9b37b724c0c4349c8af8a7a80cb2769d8a8ebf5f77dafad2cfac15798eacbef2aa575d6616a6a7ba71c61b2db1f45320a00a9604d5215b44e44b1182fc4cd75332bb555d1d220cbc6a282e319e3084480d8d09689c77297a6e452f63969fac5eef3797aac70bd9bedb03d0ecb1ae9e40f00178c00ddc7ed1dcd74375538a1f3386db4aa5a16b8f119d49205b18411a56cf324e60e65f1530d4a08dc8122461ccf326e49e43fe7ea98c2cd21501c985f5b3034323fa898b057c4dbb56e92dc1a77a32832aa64b9ad0e127215c759f2da3c1a7c8f046787e280365b1d4ec79ee3578926f244f2874219f4130079e23b14c615e0135c17eb5d2b505ce74fc907
#TRUST-RSA-SHA256 554b0b6c2c35de89af59639af144b1be36909e9700ddd2981de2b0f97cdf579c7f836efc6582646b4170d201613ff7f9c8026e04b653567198bc878e1c75af6a7122bf4578b2c6dcd92b47ab50833e8b237c765995916fa5ffbb837db8377ef58864ca734beff54b41ed2abd1d24f945a9780ad73afd4cc114bcca5c96c780b468324b9f4d419ba24c2e61e8f5ea1cd4e3d844ff48c68fc270744fcc191f749b8eee618b8ec5c4d4d67b99b9c6e867e021a8df04036c9c3981f7779eb98a22a9165e9334e6abe378ab04cf0e04d8008b2b076076705e96b440a186cec6e4ded564338315f72904e5108dfa3355e746ec8ec19847d1a0a9094026273e9dfb8c5a0d2ab04a0462d48441f337acf6ea799c78804986696bde762783b0303dfb763a66fce43c8fbd06d58401551f9bcad9923a1b17d69eeb2433942ecfba2bcc3d14bebedee6ef214a9ae53bdb089d008420fb447d9937c912e870059da819bb8a0a5b40d6552097534596cd398c554a5c776f5e92ef95e310b254d47e33d1d0eef183899edbe87904a91989be1dd2d719f6bdfb5566ad0e19d9b36d744d789f5859bade97d04acab0ab73b2771c4257849cfe8a181f574aa2013567d44d7b8d58dfa89dc9fc1fa813fcc30875361512ab4975d9831f8c480b6bfbd74560ec8bb6cf53fdf78c9b9fb1d780ee7613cb9a7336d34d16c8761663e4e4cafdbdbd011a1b
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(132104);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2018-15372");
  script_bugtraq_id(105416);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvh09411");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180926-macsec");

  script_name(english:"Cisco IOS XE Software MACsec MKA Using EAP-TLS Authentication Bypass (cisco-sa-20180926-macsec)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by an authentication bypass vulnerability
in the MACsec Key Agreement (MKA) using Extensible Authentication Protocol-Transport Layer Security (EAP-TLS)
functionality due to a logic error. An unauthenticated, adjacent attacker can exploit this, by connecting to and
passing traffic through a Layer 3 interface of an affected device, if the interface is configured for MACsec MKA using
EAP-TLS and is running in 'access-session closed' mode. A successful exploit allows the attacker to bypass 802.1x
network access controls and gain access to the network.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180926-macsec
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?52021652");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvh09411");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s) CSCvh09411.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-15372");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/18");

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
  '16.3.6',
  '16.4.1',
  '16.4.2',
  '16.4.3',
  '16.5.1',
  '16.5.1a',
  '16.5.1b',
  '16.5.2',
  '16.5.3',
  '3.18.3bSP',
  '16.6.1',
  '16.6.2',
  '16.6.3',
  '16.7.1',
  '16.7.1a',
  '16.7.1b',
  '16.7.2',
  '16.7.3',
  '16.8.1',
  '16.8.1a',
  '16.8.1b',
  '16.8.1c'
);

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['macsec_eap-tls'];

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvh09411',
  'cmds'     , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
