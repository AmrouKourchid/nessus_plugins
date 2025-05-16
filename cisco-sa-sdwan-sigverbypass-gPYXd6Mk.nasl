#TRUSTED 2b1572584afc03de134e023060cbf55c888a3ffa640ed78ff49887f73763ae2109b163ae9dd8c412a8fb5ef68eedc529d2a24dc896be83a03ef3a05716f815b11cbbbb2bb7dfaad21c397c50050137b0a94994ac321e451216e964a8834cd227af156dc7420bc54eff03f1344a5b175597db9d6cfaf15278de86b65849ede1aefb9bf9580f589fb6c8a1c9f0a40bcd92155e82047f6b1f92c4dd10c2629293e34dbb7fd6c27308250a3b56cc2f4ac9420da4365cfe18df6f0af117ffba37b3736933f1df4ecaf099c494506dea4564e152c094cd504eddee2f2b3dc3ee3ce1a4df1adcef83dce49402d9ad5afe7d7acbf126cb47c8c4c17e89d801e8167b6d64f81d071d28fc950a6ca62b208257b93fd524d4206377004fcd22aca155a3f39ed70c0fbe6b7e289bd102e1e3f574b919ea64f75fd492540bb012dc40c53006b22b061e88111768e521897d73cee2fe164d7d4d72c759324db5e7702b785d173cfc94fac9e1e23c624f60c4b9d344c2494ac831b07721ba181a8dffa99890a6d4933a6a6b0e65dfcadaf42ae47a1044c8b42023eb747fb6d851cb32044d84d4589d204b31f68d599eaf04226f2c9021ca626031deae4da301eda86e89c2b0f6438491a991e88cc19ae40f8c378aa51cc09606413b81aaf064ad42ff4021a33d347fc7d27a176ef46e686c5f743da24ab128c8eb9746ffff7a4b8bfcc4cc9ffed8
#TRUST-RSA-SHA256 3c01d2f21a1dafcee9a6296fc3c04b6c269cc826082a1d52b06f359d3df3700f6ee8689b1297797e282bcae356caf9287796a052fc74a0da98e688ae2880d31c00af1841c7dccce78c29fe09b4c40edfdd9fb390713a76cae4e623336371527c61b5e848afca21a56dbf4cbf20ec4dcfe9d7028214ba010e539d9a08e7b6d0ee5e21cc70dc90fd5f151f20bcd47ae6bf8336be56cfe5f3dc16928157fbaacdc5bb9a39fddd179b6047ec35a6e977b2c47422fbe00dcde7997017febcdf6e71a9662be43a6c23da69eee3b3351cdb85438cfba80ae4d92b63b146538101910d6fabb47e99377b1286ceaa7e526f26d6adfbb163e1b905d84e378d196ef06943df05e8d70faa7948b2e284ab4d411ed4ea0979ddd06669a5a3c2114776e02c3096ad1e831d9de3d343012438cebd554dde1174da3e19819a17e8f88a4516a3a2fee1d9f01028b7b86b8b1dc91096d60860cbe6e1cb007d40ece70f1808bfd8bd011b72aa0f4c78f160e10c76f56f5380ffacdeaab0adcfdad566e3419a847dcdeecf750a6e35ff0205ef75a9361ffc0f5989bbd57482c57b2ab588e84f59cb0c368660558e9087f01577b19701ccdbd000950df9c78bec2a11850bbc649755d7cab7e38651921929786a2468a7b3e3dcfb8ab3e07db70c5a99558ea058f91077fc5ed9229a0d5a4b3c3d2d57841aa813d59288ea27f4492d4decf1ecece81d46aa
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(150050);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/19");

  script_cve_id("CVE-2021-1461");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs92954");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sdwan-sigverbypass-gPYXd6Mk");
  script_xref(name:"IAVA", value:"2021-A-0118");

  script_name(english:"Cisco SD-WAN Software Signature Verification Bypass (cisco-sa-sdwan-sigverbypass-gPYXd6Mk)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN Viptela Software is affected by a vulnerability due to improper
verification of digital signatures for patch images. An authenticated, remote attacker with Administrator credentials
can exploit this to install a malicious software patch on an affected device.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-sigverbypass-gPYXd6Mk
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?306521c6");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs92954");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvs92954");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:M/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1461");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(347);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:sd-wan_vmanage");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_firmware");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:cisco:sd-wan_vedge");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_vedge_detect.nbin");
  script_require_keys("Cisco/Viptela/Version");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Viptela');

if (tolower(product_info['model']) !~ "vedge|vmanage")
  audit(AUDIT_HOST_NOT, 'an affected model');

var vuln_ranges = [
  { 'min_ver' : '0.0', 'fix_ver' : '18.4.5' },
  { 'min_ver' : '19.2', 'fix_ver' : '19.2.2' },
  { 'min_ver' : '20.1', 'fix_ver' : '20.1.1' },
  { 'min_ver' : '20.3', 'fix_ver' : '20.3.1' },
  { 'min_ver' : '20.4', 'fix_ver' : '20.4.1' }
];

var version_list = make_list(
  '18.4.302.0',
  '18.4.303.0',
  '19.2.097',
  '19.2.099'
);
 
var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'bug_id'   , 'CSCvs92954',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  vuln_ranges:vuln_ranges,
  vuln_versions:version_list,
  reporting:reporting
);
