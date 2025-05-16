#TRUSTED 4e39d78a7bf341e02e27adee3010a37e0b15740f54cfe7a1341e4a1d231128a9e49820561cb87d9b73a91492d7e284e3ff2a1ac140240c6021456ab869e61efae718ec4db6d81b535259894c1bdbc94a2c16ba0c22a5f1658322fe3781c36f5cb71299f9b035111acfd206003bd1366758e76d00131a91ac6e73a97ed3a2513d610a4476622276104469df28bb3ae19a0ee4d373b87976f575bb7da69a6208851f4d0c6e36839de23cd8ce7e1d2b98dcd75f07a86faa3f0f2830fa0f74e5cd06c3ed272c7cb8c7b5cee2d9e62528bac18a6b10a795ec14d784cf3eee03a40da72409d4b03352376996f8539cfb408761eec371c619755ca2a939403314c3819928850a1b8a6ec1f2e4b502018c954b25b9f18838af9fc82f0e0c2ad2d8de98815f48c9a4d8b7ad57cd475714d2866d5844f08f5333775f7f34e43155740b7f5c9b259aacaa24c5579bd98d4eddcdfc03628471f06429f028aefe90d58ee3843f0325466e578cce9f40ce9df9ad05c3e3c25eddf9310f32a77922d468fa586c04ebf6b3017129dcdb14b0659d89cd22951c7eef8258d41f93b2568f858e240677a4498def40c6d0b6161cb0c20d7198b011a98035b65e615b8c87a735452b047f43a357e515340709e0f485e9b0b9fcea19c2efa3e53926f6d6f7f13e11c50808dfdda5f40c12716cb0e10b3300ac86bd9edf236012e83b1f3e75514099336278
#TRUST-RSA-SHA256 6a384e714fa67ce3fd162bfae1b2a8c632ffebc95106a33907b606ace72d8401e6c9b62a790b80b8e5ee621754bfa76b39bbc4c8a166260ab0c90b159b048dd1ab78c1cf0d7502c11bfa99cfbe123b7a442be782db4af88cac986bbcd8e6ab2eb24896fd8e6be4c6363c331d1781211c66048c520871264560d70111145b3f23c5f1e188228b5dfd5bbdcea82d5829a6fd69257a993098ed16c0e0deda14434a8d23d82c602ab3c13110f932c20921c251164737bd7068b11359fdcd56ed3609f432f3768f7f9f61323bc326035eaf54434d82ab2687f0faa97b479cdd139ace85396ddb250a9f6955d3515920d81c95ccd22d388137160d5158208e08130a4143eb122f7845c786825c4ebf7c0380f455de91b04edc305addd33f97052cf652e0e97fcf5c548109b601c63b3f843381247a09b7fb3c38a0f4a603449ef170cb3830b163566634adbe820404cbaddb9677bee896ab2da5fdd6d27e52e416ed24922ed443ba4ed20c75f223d25cb55f6590db47a17b78861dc6b26d029e4e35a86de4274ea11cf18742734cbab45f053ece904cf6ce9688bfe0940eb7f931a2bf151a413d4deef05f698e868bfba102b4ff76ff49bdad7a15f1c3884ad972e1bafe6d1ca91d6a17e98ec507d612b453724a3dcf37854852ed0ecb1eda9aff488197aace968c556bde51251080868a69e264bc10b4c8c00b4ddcc72b5d9b8764a1
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(183315);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/08");

  script_cve_id("CVE-2023-20261");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwf75979");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sdwan-lfi-OWLbKUGe");
  script_xref(name:"IAVA", value:"2023-A-0571-S");

  script_name(english:"Cisco Catalyst SD-WAN Manager Local File Inclusion (cisco-sa-sdwan-lfi-OWLbKUGe)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN Viptela Software is affected by a vulnerability.

  - A vulnerability in the web UI of Cisco Catalyst SD-WAN Manager could allow an authenticated, remote
    attacker to retrieve arbitrary files from an affected system. This vulnerability is due to improper
    validation of parameters that are sent to the web UI. An attacker could exploit this vulnerability by
    logging in to Cisco Catalyst SD-WAN Manager and issuing crafted requests using the web UI. A successful
    exploit could allow the attacker to obtain arbitrary files from the underlying Linux file system of an
    affected system. To exploit this vulnerability, the attacker must be an authenticated user.
    (CVE-2023-20261)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-lfi-OWLbKUGe
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bc7d403b");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwf75979");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwf75979");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20261");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_firmware");
  script_set_attribute(attribute:"generated_plugin", value:"former");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2023-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_vedge_detect.nbin");
  script_require_keys("Cisco/Viptela/Version");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Viptela');

var model = tolower(product_info['model']);
if (model =~ "(^|[^a-z])[cv]edge($|[^a-z])")
  audit(AUDIT_HOST_NOT, 'an affected model');

var vuln_ranges = [
  { 'min_ver' : '0.0', 'fix_ver' : '20.6.6' }
];

 
var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'bug_id'   , 'CSCwf75979',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  vuln_ranges:vuln_ranges,
  reporting:reporting
);
