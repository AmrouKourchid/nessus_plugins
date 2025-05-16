#TRUSTED 7ffe9b7cb3662cefb714e32f831b2e2bf1eb5d04bbddf704dbece3118ec35f9802e46518575f97d7af4d66711755634e5f3ce4b66de743f6169dab0b4d21c5a0407c2028f16d520d856b5eee2329bba09cb4e0c142ad9aa67d131a83e944a49364722b30a59109abd63435512656af19b1fcd33537082dd68a44f2cf8afd8e84c95508e139cb37ef9f649b6c3f5a665123930f20223dc080a9d0bdd4e6dd1d1ffc9fa5bcc5208b3f0bc21095d0b53e9aac3dd4a1341869500cb44f396f036f114b9955c3cb413d7510a2bae373f2d2453645e11163ea8a861b81a28176521df75a9863ae131743bb0ab541eec7e02c300fd338fd8419c3e72cb3f58451106518caf1a6333287c8ca9d06992ba813fecf6065c8aa93714c79be19a6c497f258468cb24a0bb104e5c5baf0988c5aa97733f42c8302ebf6a156b258d53eeafc854371a66c71a1f846b3bd0d0384806fa3b1def9ca80f15c5d5d44d796c37d3fe2752a55c8233a1a47c2708c460046e80f7f13e6b2b5323a277a92c60572e5ac262605d12e56c646387241aece0472d639f4ef6ea70b9d0efd2715161f553f87f4a4b55b1f104adda252d23490787c2c9105e621fdd70ae978e79d9bb33a46de7a68fc73e51758533d0c2cc62758264eeeee217fefe62bde534fc06b1d2047cce6423033c0f4d37f63f72e1472051e9c9a5d4f1eee8e765e421890347dca1414fe63
#TRUST-RSA-SHA256 554c4c5f34bf8e9b2a4f5632b68a9f338f32894c0050562129e3853e9aead9e96450ddb5a361029c13ab9c579c55ad1289deee00c839d900374ece82ebaf33e9b6a456c0f4188b2c2adcc4c08d5ba8ff75162b2a618afa83fe4a95d50351d82abb2b63305c6cf9809d140495997b91d411422906e7869370945120c916cdfa02cb3ceffc4efb756f09c6af2077237906771e04a20da1dabe2234682ee61f15a07898502354702fcceeb1d2c5fcb3721e62435f641ed2d9550b404a96c3e87b27553503d1b6a31c423bc28a97edbc2869488896a11ee9f8d41f5644c49234f275b73005034f89f47014c9c368456b6c13b439a6c08f94155856e7f0f1ca4a466c2d69ef9b0dfd3745e4af87e023d560096c0c28b10819490964faefd8274dd61afd9824e4c254b6aa695d5091a0c2b3c0eafaeafdabb566b2586cb16fe001ab5185703592b3ab0b1f6bb856237e94892a61e739fc43c85dc88c90f2816ffd4973cc3237ac8de9fe9740f183ad4fb31c4b3416cae8ebc2087c50dbbf47fa6f9aeb6f301126ef54ff5afe027f3b9310aab237e4508b4632c896c4b69741302e4e6de0048da8bd24437dbcb92693aa49afa8d549fdeff243494d77d926c02ed3309f8e4720ea5800daa0a98dc3d1e3d28b76a150f29019780a8aea3ff947ed2a880e265154c87d6daf53403578aa934f7f300e344e3d135298ae9dd7de27139e2ea3
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(140223);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2020-3315");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt10151");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt28138");
  script_xref(name:"CISCO-SA", value:"cisco-sa-snort_filepolbypass-m4X5DgOP");

  script_name(english:"Multiple Cisco Products Snort HTTP Detection Engine File Policy Bypass (cisco-sa-snort_filepolbypass-m4X5DgOP)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE SD-WAN Software is affected by vulnerability in the Snort 
detection engine. The vulnerability is due to errors in how the Snort detection engine handles specific HTTP responses.
An unauthenticated, remote attacker can exploit this vulnerability by sending crafted HTTP packets that would flow 
through an affected system. A successful exploit could allow the attacker to bypass the configured file policies and 
deliver a malicious payload to the protected network.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-snort_filepolbypass-m4X5DgOP
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bff42201");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt10151");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt28138");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvt10151");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3315");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(668, 693);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/04");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version" , "Settings/ParanoidReport");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

vuln_ranges = [
  {'min_ver' : '0.0.0',  'fix_ver': '16.12.4'}
];

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvt10151/CSCvt28138',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);

