#TRUSTED 2fb9d05b6f9622e8360643e5ea0ef6f01547dcc693ff9db40e302a2dfe1a330d55c0087dcfded82c879c94b7c01595c3f5db417003dd67137bc740f6005029658d0d5f1fdaf96c17d576de775aaae96e4850174ded612e816de92f29390c03e547e8a5960d46e517905c58fb921fb15fc767dee69919f29d0b88520407d796364aa46959adac18903ad98f127766561c1974165298a4e421af3711334a7f231223fdf0b07ff079b17d872615b8a5d371c424f2ff2858944634240768c649bf1d7976ff0e36ced79f593e69a6b7f05342ac1f6622d46756cab2c42f57ea8b9b218b367c8c17c5c8c4d0110dd1e582b84d9c4d2cfa212bbf7b597c2e871caa3cbfc488f756f70711539069f33eda0fb25d0fa34323aace6e53204a945d0187aca62518be47f1e163bb4f561cad2edc27cdc56a9fb9253d2c407df101af0a703740a20394080727d0b10825b79de9d24dedc4f959c91a487d8d47e87f496d9e8804f445b58e3fae5cfc6d3b3496e33bac1728e634a8e838bc468bb1f9a20c1474f9c9420b13c22661c36a8893d00eba5e6105fec467266cbc47bb07777ab5e5a6067973d73701d6531c5ad001f1dea5924fe7ca668e76a6c8eed8495fcc9a88d11ee56d41a1e0b1e55a8953b78e2a023bdc67a09c82c65c6bb6da33999f962ae4920feb303dcf84c84e1531ecdfc798d28d9b571897e54964c3411aa5d2efa7c697
#TRUST-RSA-SHA256 1f19256b8e54a7859e361222cd9c42447e638c972f5bcd6bb6357a37497fa593767985cab990a22c3e47c3f97d21f19ee3d0aa3ebbd8638e717270bc01ddc55d8f81d52a51c5682c23fd0e8cb871cb0dbe2a7b4afc0e9cd32202fb994ea59645b5fea56256e3a900bd58e720e9bd5792e51040a6736e8cf8396b7119be6629f74e34eea1c3a99362730d44055b6d892dae9144e50818e9d7ac55fd63abc80920285e1df05c9fc11a26dd6457436cdb769ed1e0bf62fef8ee7fc89e49c9417b54b8cf0e9aebbae3c5d0a7734b620badd28b82666051f1390a03a52bd7cdcb91aec616fb211751958816c0049c892f3122ed91c2f0cd607cfd06069739315eaf1abe09335ed4b29ccc082b9ffe5518f8e6c30e0cc5415f9e31c7be9ba1edb554ff4a0e6bafd3ada9425b1ff6f0e606011bb5e8d633b4f1cedf308b76c17a71c700e67e6d486a6caa46d853515b73fecd696f44d6d28087b0dddc65aae97766bfe49687976cdfaf39fc2fe9039b4e3b0dfbdf68036234e25ae16778c7b8acc8efaedc37f76b5e651a9fb827a3d570d3a33e2a7f2c8f3229cbef150f2b4e1699d1c8815dbc7f060f5593693458bdbe1175b359793a6e0e8017c9da813b4b6ad8bceb2d028ac77d03f0e7a63d7b7be9794f6a16307b64717b1c2aa588b940bec76c5318d0fc5bb582c200ffc8fdc9c88e1fe31faf16eacabac17a12a0ae328aa05b12
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(192943);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/29");

  script_cve_id("CVE-2024-20368");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwf44736");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ise-csrf-NfAKXrp5");
  script_xref(name:"IAVA", value:"2024-A-0198-S");

  script_name(english:"Cisco Identity Services Engine XSRF (cisco-sa-ise-csrf-NfAKXrp5)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Identity Services Engine Cross-Site Request Forgery is affected by a
vulnerability.

  - A vulnerability in the web-based management interface of Cisco Identity Services Engine (ISE) could allow
    an unauthenticated, remote attacker to conduct a cross-site request forgery (CSRF) attack and perform
    arbitrary actions on an affected device. This vulnerability is due to insufficient CSRF protections for
    the web-based management interface of an affected device. An attacker could exploit this vulnerability by
    persuading a user of the interface to follow a crafted link. A successful exploit could allow the attacker
    to perform arbitrary actions on the affected device with the privileges of the targeted user.
    (CVE-2024-20368)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-csrf-NfAKXrp5
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?89758453");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwf44736");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwf44736");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20368");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(352);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine_software");
  script_set_attribute(attribute:"generated_plugin", value:"former");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ise_detect.nbin");
  script_require_keys("Host/Cisco/ISE/version");

  exit(0);
}

include('ccf.inc');
include('cisco_ise_func.inc');

var product_info = cisco::get_product_info(name:'Cisco Identity Services Engine Software');

var vuln_ranges = [
  {'min_ver':'0.0', 'fix_ver':'3.1.0.518', required_patch:'9'},
  {'min_ver':'3.2', 'fix_ver':'3.2.0.542', required_patch:'5'},
  {'min_ver':'3.3', 'fix_ver':'3.3.0.430', required_patch:'2'}
];

var required_patch = get_required_patch(vuln_ranges:vuln_ranges, version:product_info['version']);

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_HOLE,
  'version'       , product_info['version'],
  'flags'         , {'xsrf':TRUE},
  'bug_id'        , 'CSCwf44736',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  required_patch: required_patch
);
