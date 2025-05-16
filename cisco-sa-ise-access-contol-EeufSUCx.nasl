#TRUSTED 5ad5dc3af5cff1f04979ad1bc031d1a7bf1e0564a77ee40b292fdd433e87f7079722412c41b356e73e5825686f6297ee7caf4588b8fad9df2c68f47c6129285ff4728ec459d8ac88804a80a316f30e4e6257621a87d1b94d3d6433992eea85b245fe943ee8d4df7eec4ecfb54cfb3bbffc11182f50e87f1d1f10b1da3005320048c5ad398e788cc7314a406746b15a45a481c730771cd7a344d23c62957928cae74fd5d3c31b33e30b5bd27acb4b598c1da3c3e7e62f1132634c4e0e0e7d2fdccc41c4015827423ea6e405acd2b2139efc8d039c4838d737dd998146bdf8e463c9c0b333e38b38ab5ef7406c6f4c987e629a6617a45a1f9ca2b4a2ef196f0422d03f64de77651ea0a4e103a0db8890a51f6a92883e0c86b6ff4fec341dc4407787f90c09bdf48e595e48d8770a6869e211877a7984cabcd63cb241253f268448be9162924421e40a1cd3d7174ad8bb1a441abcb6b4a0ba3a679985900b794de69c2a6f501ce6481764a0dbd0cf1f92c4bbd412c98192ff925ca1fc36b34325052a40abcbf02efac02b68d08a2fc4e557707aefe5493fe8c17cc4911c9866b214b4aaa9702f4525e929a3be752d9b4e5ec019c866b226ff8e5b8e2290e6e4434def2e07180c1a0bfa2542b90b0ff36c7ee1b0380f745de41ed5f5fddba76b3c8ca8e7855fc55e166205730accfae9251434cc9876ab9f0a6d02ad2e1d86d283ba
#TRUST-RSA-SHA256 1c233fc140d8154964bb17408410a7fdeb58f931061de41c5cbc47f7a839e7306e16742652589d6367594965e14434d22facb4a9ce2605a0ccc6a39184cf100bb96fed6e0afb8ae213d6c33a04794953465e643920b1384f4d19d7205a80ad15e44046c13e35ddef2d7e2db1aee55aa8093b72e35cff71ad76c2223e05f06a74742e0ab2db7f6db09653b094e03396caefff3bcdcfecd9c1e5b1407ecd071cd535ef8edb33476da0dfcf17fd1314d1301f179ea1220c4e9aad3d9a2cfc42fab70d1626e18e312de2900315aa94a2e5041c98742819a8f0f80d21ce35d96bf310069124bd0d52015a0045d89154fcf857e13d11df908b47c5a5b2c248e4bdc90d462c7974947da4cb312b8ac4235965e53cf99609762331c8ded3272438d7f41c0b791f6dc955549b32f209c0decbf7a765fe6a1c4ea9622098434e0d97f44ab20b5f5ae093f78ceff7c076e33506b1561c1e02aadcd29ea0ff582dcd2df07f4f36e2b24f17994a91b80bce4a67063f2485b02145667200bf6e1b5f03a9c4b03849583657b0152c91c03c0e738fd83dd9671991efa347aaae3ae97fc61ee853eb4fbb030136ec13fcb52f1b6c73974f99eb552777781836665f4ce4642062adb9a1df8cac1199f7d6b7caa9f7ccf60a15c1ccd2e6ad59e418823c419bb705af867bdd1aef1f053cd6af2e88b846820ddb4a33d15aad11e4f3aea67cbf92715ec2
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(166914);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/08/25");

  script_cve_id("CVE-2022-20956");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwc62419");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ise-access-contol-EeufSUCx");
  script_xref(name:"IAVA", value:"2022-A-0462-S");

  script_name(english:"Cisco Identity Services Engine Insufficient Access Control (cisco-sa-ise-access-contol-EeufSUCx)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Identity Services is affected by an insufficient access control
vulnerability. An authenticated, remote attacker can exploit this, by sending a crafted HTTP request, in order to bypass
authorization.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-access-contol-EeufSUCx
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8f3dbbfa");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwc62419");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwc62419");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20956");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(648);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/03");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
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

var product_info = cisco::get_product_info(name:'Cisco Identity Services Engine Software');

# Only non-public hotfixes right now
if (report_paranoia < 2) audit(AUDIT_PARANOID);

var vuln_ranges = [
  {'min_ver':'3.1', 'fix_ver':'3.1.0.518', required_patch:'5'}, # patch 5 DNE yet, flag all for now since no fix available
  {'min_ver':'3.2', 'fix_ver':'3.2.0.542', required_patch:'2'} # patch 2 DNE yet, flag all for now since no fix available
];

var required_patch = get_required_patch(vuln_ranges:vuln_ranges, version:product_info['version']);

if (empty_or_null(required_patch))
  audit(AUDIT_HOST_NOT, 'affected');

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_HOLE,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCwc62419',
  'disable_caveat', TRUE,
  'fix'           , 'See vendor advisory'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  required_patch:required_patch
);
