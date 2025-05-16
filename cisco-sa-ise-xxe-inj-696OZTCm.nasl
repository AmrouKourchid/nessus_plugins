#TRUSTED 48a2d3f22224e9b10a5292cc0328823a792bbbe1e29e0fd4e446823056f8bfb92b6c90a654d30230fe94c0310b1feb566dc2df035cd5f974a1c360eca23d944b9b62b59f4cdd46109474b96e46c4bab6f9d0c8cdc62cfb9dd48ebb4d80f99be9ec53674e3b6295dd5e095a73f3fc7b3f92c71dc3e158112fab7a8e6d55dd3554928a4304fc386f07165a6ecd8648c693da4da8334879f51ec6075b8908f5722a5d8c0c2986f20977378d0a13a8d135654ff2a275ecb9fa9081f6369d898183c31fa85ee563348a9009eba5e231cad7509d941377464bd6cacb323cbdb491d27873182870ff2ebfe8dc161053df204fc5c9d67418ca3361ea369edab6587edc8814a105265483ac2f48d3908a7544f2b42dd193916ba10678e4b8d9d49eca1eae27be1b39563570a1b8435dfb917e2835af13552b0644a0e594fed5157721ec9bd3b5e5b5f3394508a4ebc6edf0abce421881fa3e51d152338069d5f156a3e2d4d5aef9470e2176b1bed49dd535c29f6a076fa38b8ae1748ef6e7243549444dbaef36e6bfc40af5c06c499bec3d4f90e51d4f4b79eb66c3f9c2abcebba6ed5b5fcd23e5d48cd0fba8b89b20242f25609309cb801203779faa0827c243420ca99dd7aba51ee0d1943e1358fcea9304991570c9fbe9c985562ee6724a0e618cfe0555686994e3b547c07aeedcd793f96a19ce92d285c4d35bb92a1be7cf6e93e8ee
#TRUST-RSA-SHA256 7de8ca9523ab40e1d0e0d32a1bcdd33117f24ba9e1059a81f0c399979986d6ff91099c16e018aeb21bb792ead5b3e833b9eeb8094589f1648a3a5300076a7813dde2ce208740c4dd1b80889074b4ac662284a84a7ec5a82c149fc369f4255c336b2ba76b31b656cc52e06e90894c82e0826a4f638a485bc219607b023003e27a65ebf3ecde0dfa9b2c2c761120754cafb51e1eb07fbc57615746ed04ecd577b0e3b11353ec433c812a24f1d1300d3eb9725a8e0c4f06b545fae4ab9e2112d94570236b8ebf846aaeda5569b5be89fbc612832c6fb68e99ef05361dc0ce33ef3c3213334a2ea0daa4d1a8b946a083afc55f08db19188643c89918b3a36905aa2bb38a0cc2abcc370e83fe255cd25f76a47ae26778daae5ed7324d3dde67c2795414f9b2b8ca5ae1137a01892bf96bfaff4e42ca40bd0247fec8b50d3c25cab7008629ded85f5f22023d6f2ad796c3987cd28bcccb381858884b55afd97e4d024ac5bde20357bdc04dcd2bce3dfcd022d4dc7c042e384927704a8e85cbb5df5098bf1397cd4884574e29176f89a5f6f6a4963acf1352ef4e2479dbdaf5da50a5d63ec0a3764171660850bba7e2c724deffb2dab02e8c4692e5f16e1a8bc11636e97bb9281552714118ab3af76eec2a312aff7097bb9a11b6e3ebba1ff6d31b9c44f22b48ba2abd19c1878eb9194aaea2717ea71e4003f8c23a268161c06ba7ae9b
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(234136);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/10");

  script_cve_id("CVE-2023-20173", "CVE-2023-20174");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwd38137");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwd93719");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ise-xxe-inj-696OZTCm");

  script_name(english:"Cisco Identity Services Engine Multiple Vulnerabilities (cisco-sa-ise-xxe-inj-696OZTCm)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco ISE is affected by multiple vulnerabilities.

  - Multiple vulnerabilities in the web-based management interface of Cisco Identity Services Engine (ISE)
    could allow an authenticated, remote attacker to read arbitrary files or conduct a server-side request
    forgery (SSRF) attack through an affected device. To exploit these vulnerabilities, an attacker must have
    valid Administrator credentials on the affected device. For more information about these vulnerabilities,
    see the Details section of this advisory. (CVE-2023-20173, CVE-2023-20174)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-xxe-inj-696OZTCm
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5ef32e3c");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwd38137");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwd93719");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCwd38137, CSCwd93719");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:M/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20173");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(611);

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/05/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine_software");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ise_detect.nbin");
  script_require_keys("Host/Cisco/ISE/version");

  exit(0);
}

include('ccf.inc');
include('cisco_ise_func.inc');

var product_info = cisco::get_product_info(name:'Cisco Identity Services Engine Software');

product_info = strip_fourth_segment(product_info:product_info);

var vuln_ranges = [
 {'min_ver': '1.0', 'fix_ver': '3.0', 'required_patch': '8'},
 {'min_ver': '3.1', 'fix_ver': '3.1', 'required_patch': '7'},
 {'min_ver': '3.2', 'fix_ver': '3.2', 'required_patch': '2'}
];

var required_patch = get_required_patch(vuln_ranges:vuln_ranges, version:product_info['version']);

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_WARNING,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCwd38137, CSCwd93719',
  'disable_caveat', TRUE,
  'fix'           , 'See vendor advisory'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  required_patch:required_patch
);
