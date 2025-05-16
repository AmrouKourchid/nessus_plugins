#TRUSTED 3230f3587bbce443323577f2d63ddaf1d4ea74a2879327bab3e7ea57d90e64c119bb36967bed1c8202b8ca223037a1f6a173c1cd1ee5a0dd57e1e892b9b931f2d66df9d005f45b9c0dc63e8a7848a81ff4be3375fd8592389b3dfa0a56bca7216c2635cade6963b3a4f2c423af6d7b7713c091887b9680cd42afbe8f3ce321d4f505ba1d1c19f09dfdd8c5236da6843e24f0a2d4823a8b5ae67c4041ab486779f89365607c56ba0b79367d1c4bea36f30870fe00f6dc09c8097994bb9062c08075f567fb63b8a904be3e0d13d165d13be1a6d4f0c4ff9bd199e8dd8f0a23d906ecdace58c3a0e0b0edc764dbd96aba47ac879b75434f59ec2bc22d4a7c2c3e9763eb49700e3fee5976224e704b5f6c1fb6f2a7457828e1d2d1765b5e60f09d0ca222c95f0f91051f8d1fca32a341c442417d7cdd65ea48c18a2012b0674eabe8063696825a6a2a68b5bf670bf7cd48c71c5082c6978abaf3f6c3ff4ab9157060bdfa251c164b3c063128dd2d7cbf49182f9166046774db38f67a60e33e7c7cbd13dfdb73dc979397098e1d782294e785ae0393d78950f1ad2380fc7cc1b76ccbda787c3ad48ad9bbe93b2e62e94e04318f47a211cf9c912d80b01a1f067b1d65698c49607d951a339b2162566ffb227dad7f3cd74fa60466e0bb0dffcaa1e74eb261cd4bf2e7a69a5715ba008bdf010340e36e88e6c2cef310eeda476c5c33c6
#TRUST-RSA-SHA256 2d7e6c8fbf156c292290ec8df8326a4d01ea3c2e2eaa9371e2a62975d3f639a893ac22bdef73641c575e53335da26dc8767469246f8d820c30660e2ae722c1f9d6650aea885adb6d822aa923faa2954fdb1d2fb54e6ac587018012f995ec31b5759a8dfdd81455934601d83a957cb7221d162144b9390ea83c39920ab1876dd281523307d573cf5b6a938eb486736772d5fb69c4120119839d71b03fc2cead8c1cd081199fa6584782a4875045632074853f593dab434665dc47dd17d19eef1502a1252e4b8fc14b688d30c27286b5ce3b691547c6bb7551e64e7362851a647e4fa3e433a514edc2308885d70837dac8109ab43020f39c92018b45a8c21c99739b91a25c75c7b392b47b5939da7fec30dca9945619dfeaf1fadb89faa6cea8cc04127829f96afacbf0e4f7cc0ef788d17f7c923a3b7a7286dae63553486a2186196cb8e281fb7df5bdcd2d61b59b918d5f77067249775e76c3b57cefee2027b1627ff4c8863f6e99eff3e8231f34fc3aeb124e238106b696aaa32d831ce3c2a4c815220d6eced2592c5f76113e3505b6275285698d9f1d73d67b127486c5354e69190f734309ca9548288c820ae45567e9a83ac9c0cfe19f490600208abd9c835d7581fa22c396e792aa78abc71640406499133b28fa440599ddc864664c3b9de9adabde666e0fbed762956ed01208c49492abd9c2ecfce792dbf777bb59b8bb
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(147963);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/08");

  script_cve_id("CVE-2021-1300", "CVE-2021-1301");
  script_xref(name:"IAVA", value:"2021-A-0045");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi69895");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt11525");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sdwan-bufovulns-B5NrSHbj");

  script_name(english:"Cisco SD-WAN Buffer Overflow Vulnerabilities (cisco-sa-sdwan-bufovulns-B5NrSHbj)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN products are affected by multiple buffer overflow vulnerabilities
that allow an unauthenticated, remote attacker to execute attacks against an affected device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-bufovulns-B5NrSHbj
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7f3f0159");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi69895");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt11525");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvi69895, CSCvt11525");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1301");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_firmware");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_vedge_detect.nbin");
  script_require_keys("Cisco/Viptela/Version");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Viptela');

if (tolower(product_info['model']) !~ "v(bond|edge|manage|smart)")
  audit(AUDIT_HOST_NOT, 'an affected model');

version_list = ['18.4.302', '18.4.303'];

vuln_ranges = [
  { 'min_ver':'0',    'fix_ver':'18.4.5' },
  { 'min_ver':'19.2', 'fix_ver':'19.2.2' },
  { 'min_ver':'19.3', 'fix_ver':'20.1.1' },
  { 'min_ver':'20.3', 'fix_ver':'20.3.1' },
  { 'min_ver':'20.4', 'fix_ver':'20.4.1' }
];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvi69895, CSCvt11525',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  vuln_versions:version_list
);
