#TRUSTED 1c5afff289310ec405ef7f0fe7c8e889c368a7287af26812574f49c3cd76b45bc93e98124e71c5f0daf74e8fcec16bc48647abf20dc2d143938a232b425634edb1656f58ffa9b5f7646609ee8122d937ee707677a67a0a42615a1b4dfa9d595773f92d08b492c0afd6a2390dde7c632f5e81347ad3f9b507d1c23ab99137de637c89444847b5e54831b90c5249829bdc27a4fc0eca9dce955cbf368820c1c6f623da0602cbeee7d5419366d586d391b1fd87cabb4161a3fa984675ce863e1c7b85aece25b8f7255afd241b1294eb4ac3cff63ebbabab74ea66d82c5dbb537cdb0faf88b7a97d4cbfb38de3f09adedb8e87986ba40044a3d4bb8330846fe7f3371c2e161cb8f35caa35f96ce31a80763c4037704296ae66de0cd6b7a36afc023deb2dce192c5fbe4f4020ed96358a7957024ac17efb2d507aa43b17bb1be53f244c39737069cbe733d109e4e98edeb0d643e86ac91dade1a4d12a420a3b972cd1dcc374116be8ad9481ee16a705ea9ff30fba7c3094dd2ba1b57fa1687a6447acab6c2de4c25d557d74dfff7a14bd4f92d6373eade02fab01b47bf756fc6dab787b39d31754973973b55b50b2c33d87886f7bf3879b051b9d3f5360f7ddb78a31d07fed46fee5accd989bc3ac8a86716f3e785e6d63e9377b43e8cced393fc9b160951da5cb869458e4ec6b8bf59e8658b16b3ce532c9cf77c60830d58a0977d3
#TRUST-RSA-SHA256 5f61c175d0b2123a65ffaf41bbd8bf6d5081c6a698f9c1406a1ee03a8a6aa55bf1d1fff05ceecc189198fc5e6edf3a1e63708b1267b739219e68c312debe3ea8df9859fbed22101bdce5de6a03bbf430adbc72c1842db5249da44f5b00e95006d28f700fe6725bf34d1808d25166b12b9efb897382f32472ce1873f6c24977bd120697d3fb00b62c88ee9638e9cf4f86a43b7eeb693049bba045da399681e53a3dc1fa7891f4a86e8829765b280c6f1a1c3aeb28595bbdc8b6894811bd1fff3ca67d68da92a811c088a0c96b8d37b67be1884e4693056d2e355e75f3b6c1a9056e086857ed8bb78ddb9570a2aeaadb4b9df1b93825c921337a528b9d0c3706431bd5f57d4391761ed01ebe2472560b7752fc024ef05c1ecaced30bcbc1650f5a12543b72cf4dcd55bc2ad9755da4b05d5000045a172dfbbfcd15177e848043ed78fcef11e315b8d9c81a4ef69c3f607e23acd7b0f6b01659f64a1fedf2108d170bd3d9a660e94d0709989d3126479be84fd648936c75927fdf3ef9507a31bf8588ee2cf3fceecbdfe8dff211cf6d0b198cb1f5ae2942cbb8044158a8c15fb9745add73a96df8235906a487c4930e15dbc03d58fe68273f80555175719dd3dc6a2e54472637d5bad6f7d751afcf3d02e91d5af3b43f0bf9c8851d90a55127e7ca2c482b7c6699bd97d4198c2b22c7dfa8d11479445aab45ea112750d68effbfb4
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(215116);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/07");

  script_cve_id("CVE-2025-20184", "CVE-2025-20185");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwk70576");
  script_xref(name:"CISCO-SA", value:"cisco-sa-esa-sma-wsa-multi-yKUJhS34");
  script_xref(name:"IAVA", value:"2025-A-0082");

  script_name(english:"Cisco Secure Web Appliance Multiple Vulnerabilities (cisco-sa-esa-sma-wsa-multi-yKUJhS34)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Secure Web Appliance is affected by multiple vulnerabilities.

  - A vulnerability in the web-based management interface of Cisco AsyncOS Software for Cisco Secure Email
    Gateway and Cisco Secure Web Appliance could allow an authenticated, remote attacker to perform command
    injection attacks against an affected device. The attacker must authenticate with valid administrator
    credentials. This vulnerability is due to insufficient validation of XML configuration files by an
    affected device. An attacker could exploit this vulnerability by uploading a crafted XML configuration
    file. A successful exploit could allow the attacker to inject commands to the underlying operating system
    with root privileges. (CVE-2025-20184)

  - A vulnerability in the implementation of the remote access functionality of Cisco AsyncOS Software for
    Cisco Secure Email and Web Manager, Cisco Secure Email Gateway, and Cisco Secure Web Appliance could allow
    an authenticated, local attacker to elevate privileges to root. The attacker must authenticate with valid
    administrator credentials. This vulnerability is due to an architectural flaw in the password generation
    algorithm for the remote access functionality. An attacker could exploit this vulnerability by generating
    a temporary password for the service account. A successful exploit could allow the attacker to execute
    arbitrary commands as root and access the underlying operating system. Note: The Security Impact Rating
    (SIR) for this vulnerability is Medium due to the unrestricted scope of information that is accessible to
    an attacker. (CVE-2025-20185)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-esa-sma-wsa-multi-yKUJhS34
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a765161e");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwk70576");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCwk70576");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:M/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-20184");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 250);

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/02/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/02/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/07");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:web_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:web_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:web_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:asyncos");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_wsa_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Web Security Appliance/DisplayVersion", "Host/AsyncOS/Cisco Web Security Appliance/Version");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Web Security Appliance (WSA)');

var vuln_ranges = [ { 'min_ver' : '0.0', 'fix_ver' : '15.2.2.009' } ];

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_HOLE,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCwk70576',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
