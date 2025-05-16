#TRUSTED 23b5a91505b915d6853d50ee0464b16771bb23f8880aac7b2028b428026ac4a1c9e93bff7615f82cdcc68124930d4d9794a059e5ae982a06c07636749a26c924c71789420d935bc862d4c25bd1e2677409c4cee2b71dd5cf23e1cf46943e9d317d5b4cd81c8a5485c605c58e6938a7ec06c9d10b2ca1fb84b2d57eae7ad4903117486afd64e9a38aaf55d3a331c1de4582e3f1a698b82164376a7ea58be479a7f5a8024bec2f4544d956395287e7ce7855a87ce5c617851cf6c59d3dbc40134fc7533bfc33f0cec36179bb18b4eb68560e839f7d19b64d3b69788e5ef9c1fed9a9f120b72cfea20e986cd0b4e89dc336975c8c4e4ef88089fc94524da1e2f186c642f9ab0e541db08a59f39fd1b0cf8722ec254523067b1a7f7a80d399abbb0b95dc0fc4c5c11615c07842a520bc39b4de5ec4dd4c4f64defca0d6c796aa27f036e2e72d12de052acaa227e0feaf9e892ea076a2b1a613920a5e5d019265e4632004eb39fe48e1a7d5acc9940feeb5f0c09252b928c5ecfd452fe4e7af59f26f6ec47dc3e7214feb9de9daa4cbc8e3bd5c3d1769c3b67637ee0ddc94a6874eff1a64f6119247fd1674081c8173bf680a3df370071c146a094199d448db563423f1c615143bc63ad84f69d615fc00298d8d4320f436d11f5e96d3a9e1e48e50739e94afab27e105275b8d47f3a6c2b6346e0b20b798de9d958f07091031488d33
#TRUST-RSA-SHA256 39761239de963127eaba9211d0832d4e13a3af1118b0f12c400bd5d9fd41aa28017b603d4e54dee9ef2da2d0f3fd7e71f744a4b23bcf7ba4a4396826c969f77352fe41df526513bb2c570573f936a300f9b4f08ac236ba0c7f45355d5f114fbc9338e52508113f8edd2bed6033bee1896aeb86b014c358009bd7ee8eee9bee20b1b91d08ef49f9ebc6586d50e588997eb0fec8c029cf48069bcdae30a50f858e9cde262377478f38f3670184d924d6f7fd776c4b8c5d2eb7949bb0e83bcb73b6c88f7f16fafcc868306ec92739e9ca4e0a2297326a0bb3193544036e4ee284f45755f334380b9a473faf09bf6736757e5d4baeba7194eaae60be919bfa1d93300013dbea9456d95e04f86d6393cbd8389c066686f7f2276077f14a5944c5ed5efff5df4d91eefd271d4aac16213b5baddfc0205e0b7c10973f477be2eb29c2986fa4c139dd2bd5d275a42b5a4aa9fe2e74af08a35669cdebee5c7fb01726fb57f1861a724e94dfe0edc24e204b5829099e524ddcbcf259ec1230c31d7674f6b881d98b122c267262f0ceb075e9f58954d7022eecfa1c6bac1e0ae2b01e6460bd9336417becd908bc90725f96c541f9c0e66213fd2cd9887a83dcb32618cb6abd404b4607314104fded097bb765733e346bec76a2fbb4ff097ff75e5a28d43a43887e6c46f397cd3a51fd2d854c75e58ddb6b96e16d4bc900e449deb272655020
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(128054);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/24");

  script_cve_id("CVE-2019-1909");
  script_bugtraq_id(109043);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvo90073");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190703-iosxr-bgp-dos");

  script_name(english:"Cisco IOS XR Software Border Gateway Protocol Denial of Service Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XR Software is affected by a vulnerability. Please see the included
Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190703-iosxr-bgp-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ee4856c4");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvo90073");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvo90073");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1909");
  script_set_attribute(attribute:"cvss3_score_rationale", value:"Scoring adjustsed to align with CVSS 3.1 attack complexity guidance.");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/22");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version", "Settings/ParanoidReport");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:"Cisco IOS XR");
if (report_paranoia < 2) audit(AUDIT_PARANOID);

vuln_ranges = [
  {'min_ver' : '6.0.0',  'fix_ver' : '6.6.2'},
  {'min_ver' : '7.0.0',  'fix_ver' : '7.0.1'},
];

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
'port'     , product_info['port'],
'severity' , SECURITY_WARNING,
'version'  , product_info['version'],
'bug_id'   , 'CSCvo90073'
);

cisco::check_and_report(
    product_info:product_info,
    workarounds:workarounds,
    workaround_params:workaround_params,
    reporting:reporting,
    vuln_ranges:vuln_ranges
  );

