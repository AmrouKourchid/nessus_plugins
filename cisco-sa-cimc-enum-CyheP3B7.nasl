#TRUSTED 9bdbb6ca36722284fc3bf1ee516f849328f42e1ceaa004bb253daf7e156c2742438f5e3c351ac3af774f966c24225584e175062f17e27450af121c155b22f41a0d6615cf85d7992fd9285394d6292c417cb2b9f20978f4dc62b45c10ea6bfd6c19b33f1d2cec1265769c27d472ef0f1ee0cd6afd6f2ca43ad8566afdc8f7aed1930d39c2982fbe4900b7cba63ee5186dda5e8aa804ab107fe3dcadfc180ac9e16ea935e0c2aaa7d451e48b811e039f110345ee21d14849132c9e3ac766ab24cdcb84c8bf93f1ae3f9aed915f40c5b0a2927b28380ddea8ac950701189041383d0bda55c0d1f3f3cf05f5ef4fb68685beb22b53060637d613672555a55e1217f102e0eccf15668ecda79bf1a7a76343127a07acac4d56e058a2396af92dc6d5a088a5c331b61898835546b2784872241c67df06f215cc6dda1a3793c43f17a6e8308c90b1af317f2ca5e108458d92a6735fbc8045555618c93d5cedde65aa6c97e89e956950d83038f8e6f04b43a27ca1f1ff18df065dcbcac7bfe4ff53797da7c2b51f4e2a3efa911a94bb305b243163f88a707b325c892da028d6dd1f9b6d15fde2b2c721511cb2a02612f6d22a4d890555fbd57c132bc0b3cbbfdf3be9229fdf3d546d2e7a83e70645bc37652e45edba9c2bf772fbe2e5d3bbb497902357ddd07a744d576bba378612c5be2e8b8fd964f699ebd25d5527e0b80d78dd14f941
#TRUST-RSA-SHA256 3025bffb5f2cab9465fd7bd0a1c5999219e1f69c48b93dd29497e627728a6702178196dc59a0915a9b7c90267b2fc10119daae1be052f8440a026e131425eba44924db2e400f151fb94be8343e8d6922356a94c4d450465f82128d96761ff3d1c660b660248d9b0be6d4d9962b3ccb1c8fce06b7fe4229aef65cc2a3d41c70cdf0b71ab9bdc6958dc6e28f3730e37f635e610b4681f523fe3676f73f78dcc3122144ee043e3424ba8c734cb77a29b24063d0fa28a6160ba8f1aedb415be87621969ce9c5bf672c2730d301003d50dfb6bec7d7502583747de3e1d0b0cfdbb674d67b5e11ba55125e950f53ebb05928a90df79f6aaeaba15a26c42b6592b8519866998c7ffded0e501af1cf54b4d1124a8372c7384459dba64c71b32a4ab43b08629dfbe279051cf75e4f9e2fff3bfa7e46dade6bfc3a1ef406b1bb8c7286c38cfa4842f67ae7adb59a445e24215604a4cd2e1e7206207a154d445e210e53597e273c5e09e66f6b645a5ded2e4737ebf68a18d72b4e17a04e7f98d981a621e3fa4e596d12f764bff37bde55ea4fa7d5ebe343737f3d84bf8a72f309345769f637e3cc8807fda44c9f38b67eb0c779a7a2610e773a6d9e21d4ab29919d38f56bf6e435dd8f391c189dbacee4c07d619035ef41cc86e0d31553ef178a270e08d749b36f02cfedf16dee7ab2073e11bd7cbd42a84d759ce70ed0e6b905d6b9aaeecf
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151487);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/19");

  script_cve_id("CVE-2020-26062");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv07275");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv95095");
  script_xref(name:"CISCO-SA", value:"cisco-sa-cimc-enum-CyheP3B7");
  script_xref(name:"IAVA", value:"2020-A-0502");

  script_name(english:"Cisco Integrated Management Controller Username Enumeration (cisco-sa-cimc-enum-CyheP3B7)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch (cisco-sa-cimc-enum-CyheP3B7)");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Integrated Management Controller is affected by a vulnerability due to
differences in authentication responses sent back from the application as part of an authentication attempt. An
unauthenticated, remote attacker can exploit this, by by sending authentication requests, in order to enumerate valid
usernames.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cimc-enum-CyheP3B7
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cb11d05d");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv07275");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv95095");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvv07275, CSCvv95095");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-26062");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(203);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/09");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:integrated_management_controller");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_imc_detect.nbin");
  script_require_keys("Host/Cisco/CIMC/version");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Unified Computing System (Management Software)');

# 4.0(4h)C and earlier
vuln_ranges = [
  { 'min_ver' : '0', 'fix_ver' : '4.0(4h)D' }
];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvv07275, CSCvv95095'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
