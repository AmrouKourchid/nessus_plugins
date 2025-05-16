#TRUSTED 436822d33fe2876adec0cecfb7dba59e662d4baf2e7c0cf21be7474274b2f298d00ca3aec8630d9c3e4c71e9f67426046da3c47817d5f487d0284accd6ab864caace40cfca7808abd6e64f5a99363b0ddd301b45dde68000ae344a5a5d132ab44551d1ebcb2817016325f1cffb7a3d093cacc6019ecca27423224c3f0af65768929a9b38032138b6e401a4f713f3342585b97b2195fe6a560447516ad544239682a003100c198b2574bd85a709e8a42260ac100fbd80ee2ecf4c9d2eb3ed2667db13fecb949042e6867e7bc8d7bea5834b5a6940bd891f04c72112dcc591df151d40784c3bf8abc72344c30c54eeef177108e87b81ea4e14976ff5b76f886c435c0e44a85dd61f34b13956a49cef3f573bfea24b67fa8d6eaec26694dad06712bf7143bd89702551e29a9c545b605a5419c1da976cfe1f0875040344e292e5249283b27aadd287b1e9fa3be56cac2e98627277878599ddce05f78ad477488d91d6cacb9d46ce7b08b3717cffd4e0d033d855133b3ee8f7b1377acb737ea87feacccc0c192a1cf02f47a28d61ddf269265d1fb0d27f42c49f5958e1d1dc57a0e6491a388e8cbb5d413d0cf7539dddc41868a71ef982bc73f012aeb603cf05dbe686791e2f37b72e2063f1e53a02a989b7363cda358db01b64ee6172a8444598807227050faf118da42fcb6f42c2e1d7a43d9a9e60ef9804e48480ca60718b2148
#TRUST-RSA-SHA256 505cae9ff0afa685ed05806a3e68e5306bd1645c0fdd099f153314b14c6b22063039a33be941f6d761e362e35607d9efc3a2d0192e6671e25095f038203c0472e7ee4682b1745889945c62b95aba139b6a554ab619d3339a86c8d984070b072da8b2c5091738a4bb19d378846dcc4251c06f89e83fb7e8794b4aed221d619ec21d1c42e35978857f19424056b0f7996f9ec4ac6dfd949aa3160f20dd1d45578a988db59ab8f7d328b08d3a912085819d1dc67a2fb68e8f45761d73fbe83938a9d95d9c4de97932622eb98098ece7590914f8f80111d5e4046dd6fa08f69776f40df9ffd1716590354b0d8a195f45c7eb711d0e1089410371f01d0a0c8c2ffd2866246d451e0f02437601baf6c6264236c8f80d0cca78afac1970dd2ac974657db6464828813e88686eeef7171ef008a7e7984afd5c98e188c12b4e8f5f7b023a80a7ddcdbc9baca40c09bde12bb30ceb1974532ff03e6657743fdaff0a1c7d86cec15e2950b0069e3156c50c2228b0a7b0c2bf4236cb3a168f04cb788823760d1bf2438a1e983128092f80358614a3ba72b9346c587024e0d93d12e058c5c982dbe6b556d92e7a505d448149af8cac19113c069ae88a1ff06d8a69b104c55d3f85314eadb721840c2eb8b20bcf5ccc8f1922d61b38ae528d298513c471ef933766738e77bbeef7bd61639acc4b1c026b0d74810cd6ab5ed8aabaf605d8a4a1a4
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(202720);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/08");

  script_cve_id("CVE-2024-20296");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwh97876");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ise-file-upload-krW2TxA9");
  script_xref(name:"IAVA", value:"2024-A-0414-S");

  script_name(english:"Cisco Identity Services Engine Arbitrary File Upload (cisco-sa-ise-file-upload-krW2TxA9)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Identity Services Engine Arbitrary File Upload is affected by a
vulnerability.

  - A vulnerability in the web-based management interface of Cisco Identity Services Engine (ISE) could allow
    an authenticated, remote attacker to upload arbitrary files to an affected device. To exploit this
    vulnerability, an attacker would need at least valid Policy Admin credentials on the affected device. This
    vulnerability is due to improper validation of files that are uploaded to the web-based management
    interface. An attacker could exploit this vulnerability by uploading arbitrary files to an affected
    device. A successful exploit could allow the attacker to store malicious files on the system, execute
    arbitrary commands on the operating system, and elevate privileges to root. (CVE-2024-20296)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-file-upload-krW2TxA9
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0a5ee5de");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwh97876");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwh97876");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20296");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(434);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/19");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine_software");
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
  {'min_ver':'0.0', 'fix_ver':'3.1.0.518', required_patch:'10'},
  {'min_ver':'3.2', 'fix_ver':'3.2.0.542', required_patch:'7'},
  {'min_ver':'3.3', 'fix_ver':'3.3.0.430', required_patch:'3'},
];

var required_patch = get_required_patch(vuln_ranges:vuln_ranges, version:product_info['version']);  

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_HOLE,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCwh97876',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  required_patch: required_patch
);
