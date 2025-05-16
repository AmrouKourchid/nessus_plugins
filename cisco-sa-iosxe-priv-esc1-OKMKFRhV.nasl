#TRUSTED 08173b1fc186c0c1db6e301c5860142ebe1ed50b06ea08a2578b20195f231dab5569f719c60e4853ecf36b7e1ef753b3e9260bf4bb891334a2993b1e4e63e51bd37cfee6dcd904a7d40713819ada1a40547bf1a040be1d2b3c2c7eac7bc45d079a1084bd8a0b356054580ec398bfa370a4c785545a485aad5e71aed92022efb776f5cb2fbb1f5b76676251625d904e6b58d51f5d7532d4e75092addd683b3aba77389b0da2e18edf11a29f9d132c26344f0d2ad856026dc0df43c944f3257d61bca38ab1dee17aeb5e41e6f1be100b321f312c96830203907567270650b1393710c46181d65042a274e38a78a8984366bdf70259b7c1278c96e79fa4073c87186fddd89476d1efe752c76c9bcec92ac333c36f99540ec24aeef58545cca8e9ead8fbfa61decd7331b2d3b0d7371c6795ef52fd00ed7fd319a6cbb86e8ac2bed10cbdf6dad8eda10024c42407c16b2a77d8d1011963f0bdd32ca6e998d4a5052ea92dff06297c4b0bb8cc370635e7993b1f5ef19645bd3be33680ec475fdf0d86b5e7b26afbefdf2469f69334765b373fe0026a6ed9d21442e43cc7544402665a9f4be265ccd9db219d2731f8c3ae6c2d6f78ff27579b7a2003304dd7c658b179db38847d73a99f1afa94b5df7f08dc6055991065611b90f172902abfd9c6c3e096bc447c0cce310abc5fbef7d106e16d0e4a745b31effaa7804839992db4059c
#TRUST-RSA-SHA256 48ef2681d5087d8aa3d675a2208a1b90ea822e008cf6fbd6358f3bb4bb0ca810d58825a2fb691b7e12224ff2e9e10a98442912047acb5cf252962e570038aad4ab73d505d33f363dd2a6f03bd42857401b9d3e12e78170c0705c48066cfa7dcafbca2697587a05a1ab0ec9a0f8cb3e7e99bf096083f6351b57239d722d2220c51053397d0814ab14e1982e3efbbfb0303a00dde5bd402a517b0ca85bbe7f11788bc2657af6428e81a5ac6711fe68b4817464c893d63b80e71def2dfb8f718e0db9da8cad3e25b08417f9621363a1247120110a7a2b94be573c133b8d2062916e2e5cb7f571cf7a34ff58908d593d9250c495915cd97192e0ee7de78d015a5923f12df56ba28e412318f54477719e1782f5f4dd474ffa3b9aa95e91366a0e9abc2c15ee8f3de5e40a21f01c6fb6f6c3ddb43c630b63755c2fae18845227475d24fa75101fdf551cb3233beee49ee1417f1a4d19ad8b160c5e45ca6ed1c52c03498e0d84bd98a5766a6423e3535c8ebb08235f41a84095064bcec496648e4e95f41a4b21bb87d6388a7ee3d92073ad65b7b7f743c37f227b7190c9c5926ea956271d340808cdc7a0026e7f0fe076a895c273eeebd19deacad6d19124628187e8d2bee3a087090e2db4006a10f1a932419d4ca7aa919e7e46a5bad16c22c6f825ceafa369955b616faf4c0ab55abdbe1d06f7e8c02490b03653f7499fdd7016c430
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(151375);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2020-3215");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq20692");
  script_xref(name:"CISCO-SA", value:"cisco-sa-priv-esc1-OKMKFRhV");
  script_xref(name:"IAVA", value:"2020-A-0239-S");

  script_name(english:"Cisco IOS XE Software Privilege Escalation Vulnerability (cisco-sa-priv-esc1-OKMKFRhV)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a privilege escalation vulnerability in
the Virtual Services Container of Cisco IOS XE Software could allow an authenticated, local attacker to gain root-level
privileges on an affected device. The vulnerability is due to insufficient validation of a user-supplied open virtual
appliance (OVA). An attacker could exploit this vulnerability by installing a malicious OVA on an affected device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-priv-esc1-OKMKFRhV
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?35677f5f");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq20692");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvq20692");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3215");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/06");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

var version_list = make_list(
    "3.8.0S",
    "3.8.1S",
    "3.8.2S",
    "3.9.1S",
    "3.9.0S",
    "3.9.2S",
    "3.9.1aS",
    "3.9.0aS",
    "3.10.0S",
    "3.10.1S",
    "3.10.2S",
    "3.10.3S",
    "3.10.4S",
    "3.10.5S",
    "3.10.6S",
    "3.10.2aS",
    "3.10.2tS",
    "3.10.7S",
    "3.10.8S",
    "3.10.8aS",
    "3.10.9S",
    "3.10.10S",
    "3.11.1S",
    "3.11.2S",
    "3.11.0S",
    "3.11.3S",
    "3.11.4S",
    "3.12.0S",
    "3.12.1S",
    "3.12.2S",
    "3.12.3S",
    "3.12.0aS",
    "3.12.4S",
    "3.13.0S",
    "3.13.1S",
    "3.13.2S",
    "3.13.3S",
    "3.13.4S",
    "3.13.5S",
    "3.13.2aS",
    "3.13.0aS",
    "3.13.5aS",
    "3.13.6S",
    "3.13.7S",
    "3.13.6aS",
    "3.13.6bS",
    "3.13.7aS",
    "3.13.8S",
    "3.13.9S",
    "3.13.10S",
    "3.14.0S",
    "3.14.1S",
    "3.14.2S",
    "3.14.3S",
    "3.14.4S",
    "3.15.0S",
    "3.15.1S",
    "3.15.2S",
    "3.15.1cS",
    "3.15.3S",
    "3.15.4S",
    "3.7.0E",
    "3.7.1E",
    "3.7.2E",
    "3.7.3E",
    "3.7.4E",
    "3.7.5E",
    "3.16.0S",
    "3.16.1S",
    "3.16.0aS",
    "3.16.1aS",
    "3.16.2S",
    "3.16.2aS",
    "3.16.0bS",
    "3.16.0cS",
    "3.16.3S",
    "3.16.2bS",
    "3.16.3aS",
    "3.16.4S",
    "3.16.4aS",
    "3.16.4bS",
    "3.16.4gS",
    "3.16.5S",
    "3.16.4cS",
    "3.16.4dS",
    "3.16.4eS",
    "3.16.6S",
    "3.16.5aS",
    "3.16.5bS",
    "3.16.7S",
    "3.16.6bS",
    "3.16.7aS",
    "3.16.7bS",
    "3.16.8S",
    "3.16.9S",
    "3.17.0S",
    "3.17.1S",
    "3.17.2S",
    "3.17.1aS",
    "3.17.3S",
    "3.17.4S",
    "16.1.1",
    "16.1.2",
    "16.1.3",
    "16.2.1",
    "16.2.2",
    "3.8.0E",
    "3.8.1E",
    "3.8.2E",
    "3.8.3E",
    "3.8.4E",
    "3.8.5E",
    "3.8.5aE",
    "3.8.6E",
    "3.8.7E",
    "3.8.8E",
    "16.3.1",
    "16.3.2",
    "16.3.3",
    "16.3.1a",
    "16.3.4",
    "16.3.5",
    "16.3.5b",
    "16.3.6",
    "16.3.7",
    "16.3.8",
    "16.3.9",
    "16.4.1",
    "16.4.2",
    "16.4.3",
    "16.5.1",
    "16.5.1a",
    "16.5.1b",
    "16.5.2",
    "16.5.3",
    "3.18.0aS",
    "3.18.0S",
    "3.18.1S",
    "3.18.2S",
    "3.18.3S",
    "3.18.4S",
    "3.18.0SP",
    "3.18.1SP",
    "3.18.1aSP",
    "3.18.1gSP",
    "3.18.1bSP",
    "3.18.1cSP",
    "3.18.2SP",
    "3.18.1hSP",
    "3.18.2aSP",
    "3.18.1iSP",
    "3.18.3SP",
    "3.18.4SP",
    "3.18.3aSP",
    "3.18.3bSP",
    "3.18.5SP",
    "3.18.6SP",
    "3.9.0E",
    "3.9.1E",
    "3.9.2E",
    "3.9.2bE",
    "16.6.1",
    "16.6.2",
    "16.6.3",
    "16.6.4",
    "16.6.5",
    "16.6.4s",
    "16.6.4a",
    "16.6.5a",
    "16.6.6",
    "16.6.5b",
    "16.7.1",
    "16.7.1a",
    "16.7.1b",
    "16.7.2",
    "16.7.3",
    "16.7.4",
    "16.8.1",
    "16.8.1a",
    "16.8.1b",
    "16.8.1s",
    "16.8.1c",
    "16.8.1d",
    "16.8.2",
    "16.8.1e",
    "16.8.3",
    "16.9.1",
    "16.9.2",
    "16.9.1a",
    "16.9.1b",
    "16.9.1s",
    "16.9.1c",
    "16.9.1d",
    "16.9.3",
    "16.9.2a",
    "16.9.2s",
    "16.9.3h",
    "16.9.3s",
    "16.9.3a",
    "16.10.1",
    "16.10.1a",
    "16.10.1b",
    "16.10.1s",
    "16.10.1c",
    "16.10.1e",
    "16.10.1d",
    "16.10.2",
    "16.10.1f",
    "16.10.1g",
    "3.10.0E",
    "3.10.1E",
    "3.10.0cE",
    "3.10.2E",
    "3.10.1aE",
    "3.10.1sE",
    "3.10.3E",
    "16.11.1",
    "16.11.1a",
    "16.11.1b",
    "16.11.1s",
    "16.11.1c",
    "16.12.1y",
    "3.11.0E"
);

var reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvq20692',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
