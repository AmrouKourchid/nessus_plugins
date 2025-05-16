#TRUSTED 5875fcd23fb538666da56a3f4db1bc93223ae77cbac4ed0f39521a75d9e4578ef84856c9532c75d1df74880d838ef19c04d60a60fd1f7b89516a226c07865362f8c9c9a04d95465f7d17894365f6a8c61288b2bbd9b5307016db56da7baa2ce28b625022ca1187877e4a396b5b2dbcf5c88e8ed8136d34e49259e5ef9c06b440e707fb5cd48246e66bc9401418a8b45f99842e46c8bd5feac0560e17eebe19dc8fa8a5d7a99798563f56cf57b074ff2d6af9642519cfe7d68cfff2b72e6cae0e0e397ff87792301f9598bed1299e824c2ea4bda2764860711720db87d6013f96754aef94cf4f3b7d8e4cc0e0d1abcf8014c95c2d1a45c508b656d32c5047ab49c3be5b0fe5476fb91ec5d4a91ffafe4ab709b8e51301cc87235a59f6006b2f77f3c44def4c3223779c686a1d8f86370bb947bac55934b04bc5bbbebfe976c59c6e2f2167c36385f959cd253c340ef41c73c72e12688018b2da3c9b58d96f63e0f32947e8974ac03c6844430358d48c53ce33a3faae7f0d0befe827a5c51003bad70fe0be22b743c717c35f6170f362c08dfa601b2487ff56e664d0eb443028f168fa16a3466acac452b6d68f6eaa6ad65e836dece032bdff0790d106d6798e75a9404e32498ad97afc7c3e4fbef146c15733413679629f896951726489c3d7130509e56d8e0b9dad1b1af31b3cb9b8a5a5787e32cd39fb871837d32b7d46948e
#TRUST-RSA-SHA256 3b62d1dc2fdefc81929233018d5fd06ceb6e2103646b01aab09c8cc66e962d6fb73b11d5773256eae865582179450aa22cb536cc4bd387367a2b044c34f840588e10884297ac7f75eebf7a6d809a3e225221cd9800e25519aeb6eac83e4d1dbdd9df117c6b9d9a92fe8902975213c8cfd8e11c60984bc2aefe0fca87fc62cf5d90ea0476d3143991d7e39bbc24f51322744891747870fca7d90dc7e98e56c6b2e5f80ad38bdc972eb8d1e18bd77b52433a3f3896adc1fbbe56899981a6885a5df72a5ebdb472c36b9ae078300568ac6fc1beeff6aeba79b2048242402622ca792e3547fdbb326071bf93c3f41c08ad13a3312c04a614ed687efd5d52aa6ac666de4acfd03a61d4d2ad62555d5e57e4b2948deecfea5d860abb417f346346a22bee80f8a55a29b9e8e4b5ea98a9ca2633397dbd61d1bf4f74ea25c68305539d40b45d5e497ef986fcde8e6b352a8d2cb73b23ffda2bd454b4c7ffbadd4cdc7c24aa2b126da09f80241d4e842f1d64295037f8f710f02956d84959902606dc52e0965ded9dbd0b8ff38452c6495e20de348731e9ec6f49f479094aba9cdfc9db343163b222bb09cde37f0d950302c174daeecb0c45e4b264769a5d152a1f208a7f05878eb665b11d941e1955cb6ba32eb2ce7ec045109e0b0fe0c1f6bdbcf516f96db6c29a2a9eca2668a0c81b4e72d4ef474d000a733a6b6d7670262dbe44cad0
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(146084);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2020-3414");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs77143");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ISR4461-gKKUROhx");
  script_xref(name:"IAVA", value:"2020-A-0439-S");

  script_name(english:"Cisco IOS XE Software for 4461 Integrated Services Routers DoS (cisco-sa-ISR4461-gKKUROhx)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, IOS-XE is affected by a denial of service vulnerability. A vulnerability in
the packet processing of Cisco IOS XE Software for Cisco 4461 Integrated Services Routers could allow an
unauthenticated, remote attacker to cause an affected device to reload, resulting in a denial of service (DoS)
condition.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ISR4461-gKKUROhx
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b8f36a52");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74268");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs77143");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvs77143");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3414");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(19);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/03");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
model = toupper(product_info['model']);

if(!pgrep(pattern:"ISR4461", string:model))
  audit(AUDIT_HOST_NOT, 'an affected model');

version_list=make_list(
  '16.10.1',
  '16.10.1a',
  '16.10.1e',
  '16.10.1s',
  '16.10.2',
  '16.10.3',
  '16.11.1',
  '16.11.1a',
  '16.11.1c',
  '16.11.1s',
  '16.11.2',
  '16.12.1',
  '16.12.1a',
  '16.12.1c',
  '16.12.1s',
  '16.12.2',
  '16.12.2s',
  '16.12.2t',
  '16.9.1',
  '16.9.1s',
  '16.9.2',
  '16.9.2s',
  '16.9.3',
  '16.9.3s',
  '16.9.4',
  '16.9.5',
  '17.1.1',
  '17.1.1s',
  '17.1.1t'
);

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvs77143',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
