#TRUSTED 965bd9228151ffaa1d05e00cff90da9a637b1f6d410211d8124517a1f186bb852aac1c2fc7170761a9c0f1504ed21b166ff166f42747d57831412b5a23d2bdf6010d7d819a8f4e0e4f2211bbb602a31c0115ef82b17a11c7672c905285ea955ff38e4f3d5af0f97f9179481bd5e9d31fa77eb4e877d9445fefcd015907e4b1124e41d982f1367f07693278487dff06388d9e0b7c517eb8d8aa0d1f32c3438df1e36b2c023001e4ea009be3a890b5616b16fe2b0155afc3eb8690ed57a72cce0d055b3eda7fb3aeeb8e1d5e25214dc89c4e37e165ac33099f0ca7fe12c251ed46846f33a4dd138a4ebdbcfa86cad6fcfd790f5ff31cd97544c3ee8ca30c61114d06167c19c6ea460d6ff6f2e219a3773c7ed41fbd656726e8c60b159abe0a07ebc076c9af2795451e74a64545f99f4c7ae84250362f679a48706ab83e2ce8aa323fd0e243807b2f416797b404f16fe78f5a91b3226c43b11d618862dae65c19b6a3d07d3c33d2e56b7caa6e6f85b200933aeb39de81decc599bc61558dd08173f6717791ade3e31a94cb2c6faea4ff757e04e7369fbc5758ee823aa7b9797201c8c7814f043f2639ebde68ccfb3061950cc8bfa822d0fc5fae8d92b69a1eefdd89e495e3cbc1ac02b0b7257e3597ac461ac1affbcc839de098ae9f85521bc170797ed46d3b5a0c0ef0addaf08589e1ccb647865fdc448aa0cd470bc0caa7be95c
#TRUST-RSA-SHA256 aa9751eb25f3f6d69c202bfac6acc98f479b4089b55aed734bb8db131ee4c38ea380ab611de600569fc7ac5025cb3566be059b85f96e686ce9df265d16d5e05743c56851eaa319510fa1043e624b750ce039e6039a610990a74148fb52e85c6e5425ba029fd66340630aa8e629cf05a966f0c14bb3d08fda388b54ab93309cd081997374e61ec111e129c0d7b49d7ca2ecbbe901d54c457c0a4483fbbba57774101bf2142577204803f66a3db39ae6812e57b5096a9d7c045555fe6aa3d3a09035996a122401e935263a576313b8ee6f23334747527e3d5d21fb52ccdf22bb5093f53b28137d730714281b0553db7f4fe93936325741943d89c5f13e36acf4997b146fe88cd6e6c8635d8f44bf7b6268a8bbb7ffc9b271e380da71f6c9fbb4b75aaa23edc84cb50417ea5b943d1e6abcdf7868f350a8ffc26cb40da2d3eacc21626d7f542c7ba3e0c02083c15435e9906548be346ed61449b1c053097585d851393d9e913d71c8245c3fdc10106abfa75596e248c130538995f1d3cb2bf02016d300256211c1fc33a1057c153224f98bfc946fd601338ad0bfbcc77abb1bd446d407f1e9c1e6703c7ccbea812800400fbcd36a34f8d9f739f69b0772bf90235a30c6d2d59b3398fe48729575c1c12f279730eacb5afcdf21cfa1d1df84fbc5dda8fd2460d5a022437b59aa537af836d0d6825dd5152c34c56e99e2060eed5e7e
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(131188);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2017-6663");
  script_bugtraq_id(99973);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvd88936");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170726-anidos");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/24");

  script_name(english:"Cisco IOS XE Software Autonomic Networking Infrastructure DoS (cisco-sa-20170726-anidos)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a denial of service (DoS) vulnerability in
the Autonomic Networking feature. An unauthenticated, adjacent attacker can exploit this by replaying captured packets
to reset the Autonomic Control Plane (ACP) channel of an affected system in order to reset the ACP channel of an
affected system, causing autonomic nodes of an affected system to reload and stop responding.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170726-anidos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?89580ea2");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvd88936");
  script_set_attribute(attribute:"solution", value:
"No fixes are available. For more information, see Cisco bug ID(s) CSCvd88936.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-6663");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/22");

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
  '16.9.5',
  '16.9.4d',
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
  '16.12.2a',
  '17.2.1'
);

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['autonomic_networking'];

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvd88936',
  'cmds'     , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list,
  workarounds:workarounds,
  workaround_params:workaround_params
);
