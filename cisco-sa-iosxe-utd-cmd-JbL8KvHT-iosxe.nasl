#TRUSTED 5ae9ea03665f92a7569763fc80a13aa10f964f8edd045166a6df0bc03649c490677ce4a9e0e8c35da4b71926cc3ac8414fef1dd134fcad4e3790e3861f6f56c12c160dfce9cd17626f82246516456966de8fac55784b040b4abe476564a50ff8632f05b3a3783f5ae8a5dc6ee0b40a0bc96b168ae87f95a6778477e910c602eb179c7040d3bb48b51eb8ca7405d39cd6d9044a28920d5c4fe11610e37f0c113b67ca6f6175a3a69f500a47b8bfe04b6bc0c4cb0e1e241c338308a8a5995a413e0233219cb8aa8d97131ae516461ba37b4b3821e8e758bf1509cc9b8c71be01a678719afd71a67bfa2a97e25b69f42ff1ad233fcd44f62c4885908df7afb4750c2e14b48efa99e2e37b09411e4b8446e2a84fa0b63ff831f943ce3e076ed75157fdb458d1f69c393fc9e6b1b24603af7d9f537af7b99e4985cee97578deedb34e53578d9d605ab687bda5aa9c6e3c3a7db40e2fe59775b4813d7b3df718d0c007db64ac0b338d9b14f47673c655a56cf9fb15af61c23cf231184e13ba605083591320ea99ad25c63b932cd829311c9e839c8d3690cd29cdbabed359662bb33408d44c4396a8768624604c3626d473eb31cc1b9f86241a87fa9359e394936272ec3e5d84ec110d61abae49bde0ea588168910e6d466524e1a812c1f96e39022aba380d2e275bc7790edb8deb983e1346c1a48152593859754e25c335a8bfac4d0e
#TRUST-RSA-SHA256 71fc974e6172fe859f8b708e05c1f15e49d63e8ea6bc36d1f32467af49c0ec25b7d68d7f20219b78f174a0dfc34e2a7ee46697b94389f9131a35c202359b85a51e7709c67f81199c38b43a9886e2e012387220d27e76661ed518a8fea795a0a4ad4c25191030d5675e645c82854c0a315d4d135c3f9d6a172ecc5c23aad65b089496b9a1953e473f7968c54988279b7af95acce7f003dd6f91cb40b6b1e6c2d2116300aa3802b1a4b80e62b3a746d975c0f0013a3ffe9dd7c3d475b3796e3416e03219aceaf2cd672522a9927dcf9c6858e1e82220e7efd873b13596fcefa493b12bae5da6d5f0e2c5e06b7bb18cf67706a4f591c7a50609805a7841e388848845b2cb6a71239b68df05082547e1a1bf86d147ee7766ebfce67a39b735b187e6620d552b2acb1b2beed0cd654d3bd44ec0d619934e58c287ed20e9d474d86be351baf1b94f964e1fb46f9d05fbaadfbf2c67fbef6b6c05690e0444b8810fba2addb0554fb14f191b5b912c24ea74b6f02aa742e79b6f3f6c8e4b7176d91be7f8485b8d7449feb5e6432bdbdd71be21092f1322e879bdbb98a96afe41351b3b97c6b66dd4edc9f543c1a69135add17c93d13df2637602e6495c4762306842a9e4012a4b0971f6171f2963587c78f91fa7ea0ab25b291b106c3ef31d1c24d3a1a889bf593115b8cf963a56538287e104c36113b274df66fdd81df6d0f6455f332f
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(192623);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/27");

  script_cve_id("CVE-2024-20306");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwh05263");
  script_xref(name:"CISCO-SA", value:"cisco-sa-iosxe-utd-cmd-JbL8KvHT");
  script_xref(name:"IAVA", value:"2024-A-0188-S");

  script_name(english:"Cisco IOS XE Software Unified Threat Defense Command Injection (cisco-sa-iosxe-utd-cmd-JbL8KvHT)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS-XE Software is affected by a vulnerability.

  - A vulnerability in the Unified Threat Defense (UTD) configuration CLI of Cisco IOS XE Software could allow
    an authenticated, local attacker to execute arbitrary commands as root on the underlying host operating
    system. To exploit this vulnerability, an attacker must have level 15 privileges on the affected device.
    This vulnerability is due to insufficient input validation. An attacker could exploit this vulnerability
    by submitting a crafted CLI command to an affected device. A successful exploit could allow the attacker
    to execute arbitrary commands as root on the underlying operating system. (CVE-2024-20306)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-utd-cmd-JbL8KvHT
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?30f38edf");
  # https://sec.cloudapps.cisco.com/security/center/viewErp.x?alertId=ERP-75056
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a1da659d");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwh05263");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwh05263");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:M/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20306");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(233);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/03/27");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

var version_list=make_list(
  '17.10.1',
  '17.10.1a',
  '17.10.1b',
  '17.11.1',
  '17.11.1a',
  '17.11.99SW',
  '17.12.1',
  '17.12.1a',
  '17.12.1w'
);

var reporting = make_array(
  'port'          , product_info['port'],
  'severity'      , SECURITY_WARNING,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCwh05263',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
