#TRUSTED a4c2433bf19c6ef1622a4c6f699ad3db72033df223a3772e36532247faecfdb41da953b62cf5aa2072ab50ef967ca85de5300150f92bca8d4ef3cba4fec2267b27c5bb3337d4439658f53eb8975f8f17e5933667a1bd4e84f352cd51a7659576b3a3dfbaf4a57c051f55b5f1b562d412226f09c72e67ec93acdd107a9c63b2aa98fa15891124074079d3a10785695040c0837ba45100fb11232091c12e39fadc2eab9fb8c8d7d1a73b0b97e4a02430ed21655bbe720f92e53cc50daca3d249cf87d94e0b280fa252d688ba1e0729eae936bbc2e102e33908520251d369531b400555d435a769ec11e36dc620ad35d703b0e75d1ee14fca403d3d638d40abe3ece21cb6ba3f324014154facf3e75d16d8c482bd116c227066b41d6a2fc89870f81f968e4cb665e13ff79500c08b6668dd2b4968918f21158ed201056c903950e4d3e0eba0820761d21f3ab62ef5b32b44a6b9d3b1a0be4bb5ea469fc49dbc16dba137027c7bef38547bb2728f025e25078e61f47487ab924c0d382bdc094c0f8bcfbdea1112cc03124c2733186d12e5f1104ba643415ba491566a5cc53ac039735dfd75d160bd97e7f471899acc9701436d90bf12149dcdd56fe8f1f4a7b2bf8b063e5b8c9d8605ede4da8aaa7d354af90fc2495325ab3d328b781a6862403c3d8c308f66e5483a93eef43b4026e882ef6210ee9869591ea84822b6f51d3c7c85
#TRUST-RSA-SHA256 8cb91a33ee20c25a30552b079f5b7d354f3f0e054cec5523fe4e462c476bb2a72c32791a9b86b33da2f4ecefbb28a1d5ac7f00d55e10a18370dff0fbcbff38621e3946c46c65bb6845230e8056fee39fd3c0635a694dd21cc3cf6bb5e3078b565d369c04c3675904e2a76fec98917c8bb6ea7af41c0a690bf17dc57ff053b656e87d5979b11ad14dee13830d6c4fc9421341f2040e77e6b0be97e0ade55e8f666f7d4fba76f87100b31f41c660e9bea60126221a6ee94783a6a14f85a3078b5a0a50be58e90caf9c10691cf542ab5326c518f71a110dc3dae72846c8419bc69c6f7077af0ad718c58c7f12ed7c98e17da96c589d45f4c9eba4c26eff15e0e83641bfdbaf38b178a3c8149de112bef9abaf85e6d75ceb2d71253394307bc2fe139733062aea67de963bc17f9187aae7cf80aadf9511ee54a98c17997198fe584864b6d7faf9ad2a1467272f660bdab7e19c7a5a62226b75f09689e23769e9810c23eb7fe8e2915c97062212a6ded1c9cb613d458fa8978f0bcf6622b8ec6a06fb70922d801cbdcbd59564ef7151de29a68350d067c4c1fda3e7aec3f24ec257b865a12dc46a7d455f395f93a10a5efb1870c9330d0cc790fe2c1ed193aa72e50e93b7597238503f6f8a567c31dffa46d7f0dc03a7e2b52210040693db63646a85372e59115c5f76b318266f74eb54dd18510743bdd5ac531e92904d571a509bd4
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(186212);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/10");

  script_cve_id("CVE-2023-44487");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwh88665");
  script_xref(name:"CISCO-SA", value:"cisco-sa-http2-reset-d8Kf32vZ");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/10/31");
  script_xref(name:"CEA-ID", value:"CEA-2024-0004");

  script_name(english:"Cisco Expressway Series / Cisco TelePresence VCS DoS (cisco-sa-http2-reset-d8Kf32vZ)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The Cisco Expressway Series or Cisco TelePresence Video Communication Server (VCS) running on the remote host is
prior to 14.3.3. It is, therefore, affected by a denial of service (DoS) vulnerability, due to a HTTP/2 protocol-level
weakness. The HTTP/2 protocol allows a denial of service (server resource consumption) because request cancellation can
reset many streams quickly, which could allow an unauthenticated, remote attacker to exploit this issue to cause 
Cisco Expressway or Cisco VCS to stop responding.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-expressway-priv-esc-Ls2B9t7b
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0b350287");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwh88665");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwh88665");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-44487");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/12/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:telepresence_video_communication_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:telepresence_video_communication_server_software");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_telepresence_video_communication_server_detect.nbin");
  script_require_keys("Cisco/TelePresence_VCS/Version");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco TelePresence VCS');

var vuln_ranges = [
  { 'min_ver': '0.0', 'fix_ver': '14.3.3'}
];

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_HOLE,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCwh88665',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
