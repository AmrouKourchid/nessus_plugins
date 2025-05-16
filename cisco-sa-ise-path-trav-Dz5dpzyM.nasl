#TRUSTED 114c4f124a0efdd6b11a6eac3178ea480a90878850cc5185058cb247ec23f3fb34bcb2fdfc9c51d1586f5bc3a4d1611e07532fd493974bff55109191f0475ad3cc4480b3c09a7e5482ce199da4ef19862affa9023d3f43271e522aa3a610dedfb5dec18aab2ada0a6fc869cf68c82e50f564a9562aeef23183b4fd7703d02cd1a52e62fbff7a7fcc688021393850dff3ce15d69c9d7c6f126fa8f2c942abb68c84eb839a487420d5a7d6aedfd2cfd5d6e4256a47974f6b044740111f405d3fa0d396bb03fccd58b7ecfb7ae52889773db2f62e8dd927cf44812b33506c30ae6301d27f416a786d8272e8567ab0a6e2d9339476bcaf6aa22547cf615846bafd9b659f91d68d803009d751b5279a3cf8485245f049e28462c565361a80cff31b0422f05bab306af9bb93249afb961b87f3aae4ffae754613a6a56ea61601cc09d94dc4f3c0281eeb86430e48245930798e54299961a6802d6f61cb4a704c70935b87338f38491a90efa96da9fe8c0e854f106c61b7483ae9b8a88c0f2441311266ef68351be54a44989bd5cf23db835b055048a3c289780f492838a0f8f8b8a28c37ce8a16bd940753b2e9a934c58b81fe8dd78ae2e7fe0d564161eeec629fbf3c568be6fc5540936bfa386c06deadbda0c14a607400dc0c61faa45390922941bf74a9b2c2125bd526de205bb959259ac146ca6559eee4d1a268b1bc6a541a4585
#TRUST-RSA-SHA256 6324456a70dad0eaea6f957d33d7f3164135981a5c9da191b07919f4e2b11a3dc89d2fb49d3abf1a243fd0807a6223f1267cccd9c7fa78d03ea21b9307a018b0c87cb8f84ece73795931066c7d1c0c8048d117298022b4a5095dffb12122c03b7d6b2c56f51dcf4aa10ae9418ca37ac95d891b9cf7fb967a961fef1b2d48ba2ce640e67999fa0d59d7c4cf96d4a482d34b6d9eea438a3de44add065b9d0de4044ff6823edc3b621d4ccf1e3a5a13f7c3b13bd8831129b3d25c5195e27a7d2b909aad02b2590e102ddc669a55667c3bcb5857695108dcda08928c60d439f1aa9a35a7ebc6f0484c56d4ad3ce7f8d9c94f7b83a6581118716ba5d75f3aa3d1368d2692a72353ea27c547c001e61b67ef7dffc347c7c9d460b5b886b9add84c646cda16bbcb6ababfd7e3687126232dd252be47b7c1bd8544426620759a2e3250f63460c5e8b8af813a968b34e4f03a3ccbb1db901f8b61ea69152064e81b481e6259d5cbab47bc835e39da4e7fa03052016e2bdab49a6f21e9719cf9e24154999640f9ced7086d32c6e8259e21ce5328af2ad12a356af401a33de266f913fb6b198d730213bd1af1424acd17fc238534bb85d702d536cc5d51ff2015f10afa033e79baeb8137400538dfb39acf6d5420206b22042f6c9f38c04fa42ac291f5c65d7697c091747e9f0a20e4c7053731eda22d1df7ef4ee2d12dac675debfc3fe230
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(166681);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/08/25");

  script_cve_id("CVE-2022-20822");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwc62415");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ise-path-trav-Dz5dpzyM");
  script_xref(name:"IAVA", value:"2022-A-0462-S");

  script_name(english:"Cisco Identity Services Engine Unauthorized File Access (cisco-sa-ise-path-trav-Dz5dpzyM)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Identity Services Engine is affected by a path traversal vulnerability.
Due to insufficient validation of user-supplied input, a remote, authenticated attacker can read or delete specific
files on the device that their configured administrative level should not have access to.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-path-trav-Dz5dpzyM
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cc691006");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwc62415");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwc62415");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20822");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(22);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/28");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ise_detect.nbin");
  script_require_keys("Host/Cisco/ISE/version", "Settings/ParanoidReport");

  exit(0);
}

include('ccf.inc');
include('cisco_ise_func.inc');

# Paranoid due to the existance of hotfixes
if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

var product_info = cisco::get_product_info(name:'Cisco Identity Services Engine Software');

var vuln_ranges = [
  {'min_ver':'3.1', 'fix_ver':'3.1.0.518', 'required_patch':'5'},
  {'min_ver':'3.2', 'fix_ver':'3.2.0.542', 'required_patch':'1'}
];

var required_patch = get_required_patch(vuln_ranges:vuln_ranges, version:product_info['version']);

if (empty_or_null(required_patch))
  audit(AUDIT_HOST_NOT, 'affected');

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_HOLE,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCwc62415',
  'disable_caveat', TRUE,
  'fix'           , 'See vendor advisory'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  required_patch:required_patch
);
