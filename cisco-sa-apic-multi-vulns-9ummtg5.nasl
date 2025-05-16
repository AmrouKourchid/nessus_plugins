#TRUSTED 4b7f033d1cfc810f5a4f8eac2d1c844514888d5ae55144660c7dd953344385365f4a709b3287532e021ae43a09965dae0ecd744804714ced7a06706deaef91297cd17921c18c1ad6943578f952f12f5901ab2c2f25cfa58ab73bd7027447b2dfb1e3aa796a0fd0ed58a5601740056770629500062d73315d0891b6019b8c0dc74b63da0cb683b50eed12420a0a4c24ff7b03529eb3fca7b4a2a539bdd4909f0a9654212e0e38dffeeeaf2569eba7a33072717c50e35e37b2e4655f81538731f7b7cd584e8b72ebb309512511d2c66b7a3d4901f16d951f9b09706ea17a24c7a4bddecc90d1ee9ca2e2eb8fd4dba9a13c01dcb69d6af7089b21c58cb754dbef00fc85de6f8f1cf3ed35b46265324dd541b70fcc1827ba73b6f996177473d7f15293f265ad2e0818e40597403be5cb0c08620f3746f7043d5bfa6c80f801a9e5fed40a65305c3179b684723a2f3d3e07a57e1d9e0255e94d58fe92b187467e3113cc50c68a3bbb904c57154c3b75c855c8bcfaf336cadd1a5541e6def0e869b7cab86f44787916e7796c11e4062e2c9a9622567608c3a9176666ea1f1b49b40b92e12210811219a9ac2f529240ab1f0e354bcb2b5ee3a6a6c92b06273882f0bda3a859de778e609b63a72c8437ae5efa50e9c415e2d899e26fa2a2d50397506deb4941fa53fea300c7b8af6af065fab08db6d0e43f4441dfa472f8dc9a27b583f5
#TRUST-RSA-SHA256 06efea09de0afdf5743158be592a7734ae30c2b907be4a76f428eca27daaee862b8090438350f213a9fbb8d20d7e14652aaf437c2bf09ad291a418cf196f6f694f4bce18282ffea55b16790d4c15ea90a1b9f803d73071d99597f2c2fcb34895db71b18ea03cf2349fbde271e679950eb1f03e82b7daffa7ea49095eb03bedc22291f32fdd249df3e8ded8201451969f3bf214b348b944ac3e74637a8e55c300c2ba9376e83ecf1fed6f2eb1bd7b4a6f9c68049d02304571542a8492f8f1a7da6c9ae149294211c24f8846baaae540d0ab0ecacdaf05c5123bd61a2170253287b29f3ef5796e5fd7a83006e4ac4ac10a8fe7c2541ab0c64a8bccb38f6847eeb60776ffb8fc5ee3c2b761b0f5f6426587bde7bc573a94fde8c09b2226f373281e841ffa365031ee63b3a87765cc8bcfd8fca0c8736190797003ce772a920fe59411c5ef52884d64e7f9792bff0cfa59690cda6cd503f5d9459fd171f30c057d2bcdb46acc4ff2b87976ef3fea7b9a17e6e103fd3592890351a18441efcc958277c7867f987d940fe60da4817afd3efdb3d269486602a7d4af5004b7b63b4170bff80db0fea36cadae347c2d7082f40f53fc0946b836d341c6fae5c308555dc155bfc4ab23920559cbaae0afd8f16e34fb8f8ea39f6821f5c968bc4561046c6549ca97458d2eff10f4dbb786d96346cd47f41adf0bd9d953fd99b1b87ea6960357
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(216917);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/27");

  script_cve_id(
    "CVE-2025-20116",
    "CVE-2025-20117",
    "CVE-2025-20118",
    "CVE-2025-20119"
  );
  script_xref(name:"CISCO-BUG-ID", value:"CSCwk18862");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwk18863");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwk18864");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwk18865");
  script_xref(name:"CISCO-SA", value:"cisco-sa-apic-multi-vulns-9ummtg5");
  script_xref(name:"IAVA", value:"2025-A-0136");

  script_name(english:"Cisco APIC Multiple Vulnerabilities (cisco-sa-apic-multi-vulns-9ummtg5)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Application Policy Infrastructure Controller is affected
by multiple vulnerabilities.

  - A vulnerability in the system file permission handling of Cisco APIC could allow an authenticated, local
    attacker to overwrite critical system files, which could cause a DoS condition. To exploit this
    vulnerability, the attacker must have valid administrative credentials. This vulnerability is due to a
    race condition with handling system files. An attacker could exploit this vulnerability by doing specific
    operations on the file system. A successful exploit could allow the attacker to overwrite system files,
    which could lead to the device being in an inconsistent state and cause a DoS condition. Cisco has
    released software updates that address this vulnerability. There are no workarounds that address this
    vulnerability. (CVE-2025-20119)

  - A vulnerability in the web UI of Cisco APIC could allow an authenticated, remote attacker to perform a
    stored XSS attack on an affected system. To exploit this vulnerability, the attacker must have valid
    administrative credentials. This vulnerability is due to improper input validation in the web UI. An
    authenticated attacker could exploit this vulnerability by injecting malicious code into specific pages of
    the web UI. A successful exploit could allow the attacker to execute arbitrary script code in the context
    of the web UI or access sensitive, browser-based information. (CVE-2025-20116)

  - A vulnerability in the CLI of Cisco APIC could allow an authenticated, local attacker to execute arbitrary
    commands as rooton the underlying operating system of an affected device. To exploit this
    vulnerability, the attacker must have valid administrative credentials. This vulnerability is due to
    insufficient validation of arguments that are passed to specific CLI commands. An attacker could exploit
    this vulnerability by including crafted input as the argument of an affected CLI command. A successful
    exploit could allow the attacker to execute arbitrary commands on the underlying operating system with the
    privileges of root. (CVE-2025-20117)

  - A vulnerability in the implementation of the internal system processes of Cisco APIC could allow an
    authenticated, local attacker to access sensitive information on an affected device. To exploit this
    vulnerability, the attacker must have valid administrative credentials. This vulnerability is due to
    insufficient masking of sensitive information that is displayed through system CLI commands. An attacker
    could exploit this vulnerability by using reconnaissance techniques at the device CLI. A successful
    exploit could allow the attacker to access sensitive information on an affected device that could be used
    for additional attacks. Cisco has released software updates that address this vulnerability. There are no
    workarounds that address this vulnerability. (CVE-2025-20118)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-apic-multi-vulns-9ummtg5
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0ae11ce5");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwk18862");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwk18863");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwk18864");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwk18865");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCwk18862, CSCwk18863, CSCwk18864, CSCwk18865");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:M/C:N/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-20119");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(77, 79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/02/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/02/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:application_policy_infrastructure_controller");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_apic_version.nbin");
  script_require_keys("installed_sw/Cisco APIC Software");

  exit(0);
}

include('ccf.inc');
include('http.inc');

var port = get_http_port(default:443);
var product_info = cisco::get_product_info(name:'Cisco APIC Software', port:port);

var vuln_ranges = [
  {'min_ver': '6.0',    'fix_ver': '6.0(8e)'},
  {'min_ver': '6.1',    'fix_ver': '6.1(2f)'}
];

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_WARNING,
  'version'       , product_info['version'],
  'flags'         , {'xss':TRUE},
  'bug_id'        , 'CSCwk18862, CSCwk18863, CSCwk18864, CSCwk18865',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);

