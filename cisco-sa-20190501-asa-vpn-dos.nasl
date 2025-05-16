#TRUSTED 771695140d221b3ea38c049a5d30e929a12c84325f0807a0d4376e081afc9e275f4b8ff0c60a1eb678452774580fcf62ba5795c8c8d2858367fc8eee376716d384822afc91e152e1c5f4a8e7feacaa584bd523cd77597f6de6b9070db1a438bcea151a540657ecd566b4cb55624ff80732a4949208a68081c45ee4e5090dc75dc4c848244c7196076cb4b883e0da9ad38da5cb410cd1608e6f157781b0fbba4251e5953d8658676318f3d19b0dbac8b7255a594563c2c7627b486e41e4afeca5500f9b322540e55d19a7844d629ae30c285315f642fd070d38958045173d3241c46ffb3eb92b66f594fbb22bae1ef16b64f0f8abc337e8d2346d738cc138f27aec20fc1ec33786e1cf421e9b71be80c36431f16dca4e608c71df8370e7550b477c8e0d18dffcee3291756865e25294e3e4fb78f5c47955ecf1b70d7f072b6b7b2d32890e3578a819e79127df1c99e26bad1255119ddd26fc39fc2f1b47be357969e7c6d20858dc7d5c4fbb55da886a131532e526aa53696ecf338a0d054754ec8f412c8cd5c761d66862ce1b01c55e5a5ef6de863fee42f458851305de932c70cb7d3eed915afb2545d12d1e2a8198ba24b3edca6086a58dea23ec6c1c4e85499aa25b07a55cad708ab1f372af99bed760080bbd34e8357b18df27c584483f4c2c4389083160bdc520ed915cb3be265c0129ff34af24e9b052a3d9d4f8e14062
#TRUST-RSA-SHA256 1d97ace1eca46f618564bcc89836b3c9c0516acae0674138a30ab7ace2cc092cbc58c275a1455df61e6623ec913083db9096332f6b40cfb87be04f83a3611fc1c90fa7703d46efe8b1bb05c340e258bf8b0e897422adb8ca4c6ba212e36b0414c3c18e05d9d16d0de26c0ee79eb524f829b2ea80efcce1a59b77c65706a616865dc16ebaeed09f51acb54831f31ad5fed66bd9756bb655ce99848802c9917ba14beb42488add5dc62c25f97f5f3977b4d055e3c4a25e83bdfc487b3335e3eef80fcbf28862b3433f67cb2f3f93bc688e315b115168692d034ec3b27cabc6e964bdc6e33c0493cccbb23e1e641c040dd7cfa32be3858b30b721a2bd64542f3a5a3fb4e5cbe1fc5323124d6664ff0266ff23335ba6948ede306da9a5c0be9f4d8f0e749d0acc7382180ab3f75b01bd4ff6a58cc8ebf74a8f65ade5c7e72c7649ebcc80252480d5c046766691ec27f15fe3c2b66da9f449df750c2f30a8062845a63d5130e5d65c1f804c8e0317275c9656ef8ab01090426aebb208553a1c8c12adfcbed198e853f8d843ae070a9d751a0d065973ee40a79bdd2f4284525c79d5b880c6fd6c5752fbff4372431bcb090d563d46c8b9ebfeedda2fb9845672a2a9365c47062088498c1bd27f94025e21b6fed7fd1b2055a9a3fb9d8f2ea65af9b45587cb2d39369eb050c34772d959910823da71f14624578dcae0286107a57f5019
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(138380);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/21");

  script_cve_id("CVE-2019-1705");
  script_bugtraq_id(108151);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvk13637");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190501-asa-vpn-dos");

  script_name(english:"Cisco Adaptive Security Appliance Software VPN Denial of Service (cisco-sa-20190501-asa-vpn-dos)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Adaptive Security
Appliance (ASA) Software is affected by following vulnerability

  - A vulnerability in the remote access VPN session manager
    of Cisco Adaptive Security Appliance (ASA) Software
    could allow a unauthenticated, remote attacker to cause
    a denial of service (DoS) condition on the remote access
    VPN services.The vulnerability is due to an issue with
    the remote access VPN session manager. An attacker could
    exploit this vulnerability by requesting an excessive
    number of remote access VPN sessions. An exploit could
    allow the attacker to cause a DoS condition.
    (CVE-2019-1705)

Please see the included Cisco BIDs and Cisco Security Advisory for
more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190501-asa-vpn-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?706ff5cc");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvk13637");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvk13637");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1705");
  script_set_attribute(attribute:"cvss3_score_rationale", value:"Scoring adjustsed to align with CVSS 3.1 attack complexity guidance.");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(404);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");
  script_require_keys("Host/Cisco/ASA", "Host/Cisco/ASA/model");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Adaptive Security Appliance (ASA) Software');

if (
  product_info.model !~ '^30[0-9][0-9]($|[^0-9])' && # 3000 ISA
  product_info.model !~ '^55[0-9][0-9]-X' && # 5500-X
  product_info.model !~ '^(21|41|65|76|93)[0-9]{2}($|[^0-9])' # 6500, 7600, Firepower 2100/4100/9300 SSA
) audit(AUDIT_HOST_NOT, 'an affected Cisco ASA product');

vuln_ranges = [
  {'min_ver' : '9.4',  'fix_ver' : '9.4(4.34)'},
  {'min_ver' : '9.5',  'fix_ver' : '9.6(4.25)'},
  {'min_ver' : '9.7',  'fix_ver' : '9.8(4)'},
  {'min_ver' : '9.9',  'fix_ver' : '9.9(2.50)'},
  {'min_ver' : '9.10', 'fix_ver' : '9.10(1.17)'}
];

workarounds = make_list(CISCO_WORKAROUNDS['show_context_count_multi_context'], CISCO_WORKAROUNDS['tunnel_group_remote_access']);

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvk13637'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  require_all_workarounds:TRUE,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
