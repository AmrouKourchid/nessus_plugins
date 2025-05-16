#TRUSTED 282132fb2d4823494f18c003d93ff871ef07e7fad976912ceb89121d3505ac70df021be3b15fbba5a1a36336c9b50280a6e8fde6cb9c333bd740e170f92b227550a0d3afd4e4a18771ddd4b5739188256a8d14891f283ea982234298c847ce16f6a063075f18d4aa74dae2d04efceb5a5e6c1fe9d34b1888e463b63b7938aeb7036d3764e15c8f0726077c0fc9797fac5e2ccd9602c509622f2713a153bc01037772743d20759213f24294bbccbc4d1a4684466a3d29272d9c9062277d1b3a15112cab01124050715b7d7c398706cb197260ec307960f9f983f9f639c99bafc1418e60b48ba5e1a2ecd724cbe2d0dda493e6d6feccca9137f1484ab9e9ec19f46f23ce3cd896dfae3dcd32fe5de8031da226384f9d40c4dfbe799898f0a6cdadcd4896b401a153e164c9ea9998e9c256e2f5b9a2b8b3c066e3566c4f0cc511b1fb778e5a562b8f41bbc84c4bac49a6509896bd4b2fe8b32691c066341992212fddd7d310495b148ab9ea87650eeafab8bdfbeb66c18ac8fd2f8a6f9c347f34e294f4a1026e3709f44afabb3f946b3c3be06ce7867a7d281acd87d54f4cda33fd66d09eeba8b849da51a6100b8208000f2b18d1ba3186ef39eb958f1c19d94b9ba5663d49162b0365cf9c2aa4e6c464f6ce89bce2dbd60fd6797f1897eb22cf0b82460e005776216f8b0c7f1d8f048933f33bbae2d351d7acd2d94bdc826e973b
#TRUST-RSA-SHA256 49d5648ec3cb3da3e51e4dfa18e99125e4e8860b01beb7f9968e97ddf0534691b9dadfa56ec21e9091cb8c5f3ee28289620d4e6ada42d9df3ad02f3845899a5b2b762d368bc565ebdce96c8c977efa2fc034b66217654b19ea365298b703d542b5436ca7de35d8af8f68e8cf1bb19871bc6991b3704c55e5cb6b528ffa57f35a259749d57c6d0c9ffb1c4b3ca01c53f2ac72e6d6d7f320761c88e3e0ef075199771101c529013be3a8e58b5f6e4843825834401449fcd570997358c2512ac26721bb24cc1c2c173e42c84d75d8f4429a3c81382cfa380eea61e1924551d7df5b76e4e2f0c51b4c1e058e62cbdaeda8e01dbed78cc54bfc491ac4525c9a26d5320789a5c56da3174b4373a5b618233c805a562d0941a3a871111a9c33c6da7c809726c4045b6d9fecbc5a632ce9248186f2f6871ba81a43db7f846b7efa450aa969b674f6097e1287a7bfe24ec0e2536c685b887ed82a4ba5382523e801d904d8fea0b401775e8d9923742393a9e2df0279d501b3d47afdf75c66ba0e1e81841322210113f7b05fcaff551a36985f0cce4652913338e918e8e40c82811cef4175d244bff2ca1a43feafbeffae0c01bce11dc0b154e0e4a8d114301643a304eb643de3863fc59ce03044af36e674d771b1c091dcbf72ee63dc80bc2925afa43ff6c2b9d9bdec228099ec25229ce11493515dc627868c7506a0ad243eb28b563d59
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(206980);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/14");

  script_cve_id("CVE-2024-20497");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwa25058");
  script_xref(name:"CISCO-SA", value:"cisco-sa-expressway-auth-kdFrcZ2j");
  script_xref(name:"IAVA", value:"2024-A-0548-S");

  script_name(english:"Cisco Expressway Edge Improper Authorization (cisco-sa-expressway-auth-kdFrcZ2j)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Expressway Edge Improper Authorization is affected by a vulnerability.

  - A vulnerability in Cisco Expressway Edge (Expressway-E) could allow an authenticated, remote attacker to
    masquerade as another user on an affected system. This vulnerability is due to inadequate authorization
    checks for Mobile and Remote Access (MRA) users. An attacker could exploit this vulnerability by running a
    series of crafted commands. A successful exploit could allow the attacker to intercept calls that are
    destined for a particular phone number or to make phone calls and have that phone number appear on the
    caller ID. To successfully exploit this vulnerability, the attacker must be an MRA user on an affected
    system. (CVE-2024-20497)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-expressway-auth-kdFrcZ2j
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3d8260b9");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwa25058");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwa25058");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20497");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(285);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/09/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/11");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:telepresence_video_communication_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:telepresence_video_communication_server_software");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_telepresence_video_communication_server_detect.nbin");
  script_require_keys("Cisco/TelePresence_VCS/Version");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco TelePresence VCS');

var vuln_ranges = [
  { 'min_ver':'0.0', 'fix_ver' : '15.2' }
];

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_WARNING,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCwa25058',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
