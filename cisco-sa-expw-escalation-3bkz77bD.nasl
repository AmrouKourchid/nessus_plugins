#TRUSTED 58525a365c061c3af36a04676ca13c60858e684f375daa9eb51f390a17f03891c5e793e3b192c5ce82e885c158256e68fec34b0971ea57f0a3df433b48c1dcd2f728c5b86e175d4843562c72a9bd391c779864d89f3aff194c7afa460cb519dccca3e6f8e90e9cf3a2312952a39a4b4a20bdd20481512515c173bed0b209e12d2037eda7d6c3847ee1089b5291de6def547cc418913fe252fcff8b77735baac8f8f49cf0837648de70b9aa9874b354967351ecd73959cb6e6558fda9d71c307c23239d1533a10f2564bd72f9e4437d4ec8f1e7c3b23fa3c19d0923621435290071ed8f6dd2a902ffb433dd3592b6db9cef04a40675451d6f8c0b6af902fd9bb6f35bfcf18cff6cb50dec28a141826759319f92797e7ca82e130df9ba167580085672dc4116e85fba60e84e4a2502c6fa242e0939b696f85272ac3974823559d41400262fd00913109107e5d7915b2a66112946e71df1404ed02a5c912959cfd378d842e66ecb816d0629766307c728759244fd5dd3c48462f0fcaa2e9e4674127c79a3178885c34931f8b7bf6c3bdca0ff961dfe70ea08975d229ccd0dba9ff78087fdace5641e2f74442fdff199b1a0cdac3b7c03a763535f3e6f8a56450cdf944ca7e5510194c88058524b5ce702dabbf8622483bf4ea913acaf4007a94242796c3dc9fb67135ff5cf6dde4db5a4a149cdd1f19e73ff7ff86d224de3255afe
#TRUST-RSA-SHA256 6906e0aca0e8d99e7bcdd6d535a33d751a2891ad1446da067da373d90f5a17b53bcea84429d17de7e07fe164d82b392a34c75d604cb12763cb71c25300e1a4042cdcdf7f7133efcc9adb314b7eac55eba2358e27f426bae85fe8e5bd5fdb39e66c8326e442b0047640293cd5859923a8bed26cbd91669a4ba1111090deb37e5a6d810924640261079061a9f4c0a629fbfe1f2338145ff4dc695b9a74cd8bd6dda7f382d799143337b33b1600a6261c99ce5241505b67a4af159eee226d3e957b4d7ba6deabeb193ea63c69ef4173de7a2a3986a1c524f226eec1a3285b5ed444e9f0d18d75cfbabbd44ee0c7238aaafb019e2649cee3e7c8c80cec95e7c082c3fa8283dfb45cdef90ca67b1a99f236f58d2ca52eb753ffd6ea61e03e052f56efdf22c8a4537d7c1b875fd859fe9a510f12eed3e06caaef0c19e595c966c23723770cc58690dcf7c240fb15bbc78a92e0ebd94f1d5e4a158311ba84d3e84b9c56d60d3b0e754dfa228ef4913dc976d866b07dc264f7092da30b19968d5f874bc1692e961c8394c1e3e51cf45297cab4b38e8779bbe4cef703cf214071be97548e718c3a77392e0c1c4ad08964e2f6e3a814ea7dccd4b82854ae933a6465b6a7449f883680aeafafed2241ec162dfc47ccba42a33950fabc5a2d4e68e967ba59daf6385ebf4c2ef8acddb92acb8338d1f82369b833fc5c8d64b0d8defb08f778e0
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(216525);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/21");

  script_cve_id("CVE-2024-20492");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwk75586");
  script_xref(name:"CISCO-SA", value:"cisco-sa-expw-escalation-3bkz77bD");
  script_xref(name:"IAVA", value:"2025-A-0083");

  script_name(english:"Cisco Expressway Series Privilege Escalation (cisco-sa-expw-escalation-3bkz77bD)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Expressway Series Privilege Escalation is affected by a vulnerability.

  - A vulnerability in the restricted shell of Cisco Expressway Series could allow an authenticated, local
    attacker to perform command injection attacks on the underlying operating system and elevate privileges to
    root. To exploit this vulnerability, the attacker must have Administrator-level credentials with read-
    write privileges on an affected device. This vulnerability is due to insufficient validation of user-
    supplied input. An attacker could exploit this vulnerability by submitting a series of crafted CLI
    commands. A successful exploit could allow the attacker to escape the restricted shell and gain root
    privileges on the underlying operating system of the affected device. Note: Cisco Expressway Series refers
    to Cisco Expressway Control (Expressway-C) devices and Cisco Expressway Edge (Expressway-E) devices.
    (CVE-2024-20492)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-expw-escalation-3bkz77bD
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0adf92cd");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwk75586");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwk75586");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20492");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(77);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:telepresence_video_communication_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:telepresence_video_communication_server_software");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  'bug_id'        , 'CSCwk75586',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);

