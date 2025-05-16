#TRUSTED 6490f96b53e11f05a65822377177e662fa0996a6f8009584b72a94ef1698986f81ee9a8ce2fbc304de460f2c643fe726c597104f81f6a88f03f6bd691a8b75f63ce52d9364faa57dc02f32724f5ae41dc06542b7ca7a17dca482d23376c9e1d4a66342a24bc12491af5fb1fad7fc2ee6faf7f91f2336a77d68bac7f3c5400aae4969fd51e05501d34d26cc0f4f990d3e867476193cac06550056947a2a39c0ffdd38555afe0d3787ebd6c2a8a1c4c47f2fec6702b7d15507652bc2e85db84124a7acfeac933bc08a70e966e79a62476b6fa0034ab283da40a3888f160df2b7a47c1a86a66373bfb6e8d0abc0929462e6eaa5d25bbcee3df571c41f5f03e9509928d64affa6d62d5a924f2a91026d646475fc8d9d465dd0c7858d3995e064929ae7642768731aed8f49d0f1b78cb655ff94f8cb6e81b72866938dd616fb941fac19c4e68fff2c556e9a740b2733fba0d59bfdbe65fcca5ed6cf0e74ca460fc1d6d33888242871aaf95a11a0077b5cffb66d15f1935d505e9a638b0b20e0b4ff78887ec1f9a947e16cd2834b42e34f62a578e886fa118b659d88bda2b5ae85adc38f5df633dc55362f72f57c599250cc3a0547afe91ffd6c0fff70b09baedaafdda1ea57cadd5d7c7fa9525c1a34bd3220de73d95eb32978b266466bd773b8121ac91ff35a97e29f4c3b8c936e7a0ef2bd1eb76efbba413e4abfd037e3e33387cb
#TRUST-RSA-SHA256 a6d6d0b6b6d6bcf84325cddd36cc1723560c04e0d3ea5724d23158530abb73656457a3a33ab615bbd9e9679329f6496c17cc27a72511fa5e12cc229698557b294177dca18c9ce8b316a3ec165c65b83c50bc3ae02a1dcdb29269b8192a003fc851f4614126eee6e8c9472fbdba1a9bdcd45558ca628ef2840a8f423cc3d8f34c9cfecb1681bffcdaeb3b1038c319287ea9a64c4678ffd5fff027f1bd84a1115c8b20952d5666538459b622d1f9739a4a11a0a1a7ba14326a93db735421913d2c3ca26d51888b84a62d9ae719c6200cca86e2a6de3ab39160e8dcbe4e2574c69b9b7c408ea327bac5002d5432249e7f52f67b5be96b7b5e91a3d49650dd092504106491de37da4bd488182d02aed0da33913b3dc6df0b6bab7acb2b14786a38b1a07b4039ee8cfd0bea42a81aa95711bae1b4092d67fed8449facb2097db88fd75b960e14280d963ba73d4a75f201dbf10f326bb432b05c91055f95e01f150cbcd2f441254ccd3c4fd9f681d4d8b25034fec007aa1d4e5a536a33ddab50296db2d6e1a3c48e8338d840515dc219812ea717cd9be45e66abec86a5ca797abe07ea4ed8ca498344a37eed4fb4267aadd551a9548a4cba4fb9ec9fdd69512da4b0f4f25480015f1bb1c45ebfd63739197a378a6357ceeee0862fa145680c04e8f2faf763749fde33f0ca36d88d9fc0be73639f7f74adf629058674a84efa4a94b569
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(165534);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/10/10");

  script_cve_id("CVE-2022-20775", "CVE-2022-20818");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwa52793");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwb54198");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sd-wan-priv-E6e8tEdF");
  script_xref(name:"IAVA", value:"2022-A-0391");

  script_name(english:"Cisco SD-WAN Software Privilege Escalation Vulnerabilities (cisco-sa-sd-wan-priv-E6e8tEdF)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN Viptela Software is affected by multiple vulnerabilities.

  - Multiple vulnerabilities in the CLI of Cisco SD-WAN Software could allow an authenticated, local attacker
    to gain elevated privileges. These vulnerabilities are due to improper access controls on commands within
    the application CLI. An attacker could exploit these vulnerabilities by running a malicious command on the
    application CLI. A successful exploit could allow the attacker to execute arbitrary commands as the root
    user. (CVE-2022-20775, CVE-2022-20818)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sd-wan-priv-E6e8tEdF
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7f045512");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwa52793");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwb54198");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCwa52793, CSCwb54198");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20818");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(25, 282);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:sd-wan_vmanage");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_firmware");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:cisco:sd-wan_vbond_orchestrator");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:cisco:sd-wan_vedge");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:cisco:sd-wan_vsmart_controller");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:cisco:vedge_cloud_router");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_vedge_detect.nbin");
  script_require_keys("Cisco/Viptela/Version", "Cisco/Viptela/Model");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Viptela');

if (tolower(product_info['model']) !~ "vbond|vedge|vedge cloud|vmanage|vsmart")
  audit(AUDIT_HOST_NOT, 'an affected model');

var vuln_ranges = [
  { 'min_ver' : '0.0', 'fix_ver' : '20.6.3' },
  { 'min_ver' : '20.7', 'fix_ver' : '20.7.2' },
  { 'min_ver' : '20.8', 'fix_ver' : '20.8.1' }
];

 
var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'bug_id'   , 'CSCwa52793, CSCwb54198',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  vuln_ranges:vuln_ranges,
  reporting:reporting
);
