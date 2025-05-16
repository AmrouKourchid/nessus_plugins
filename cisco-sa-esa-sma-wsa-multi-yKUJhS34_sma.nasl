#TRUSTED 4fd35fc29c2e8c7fb0c836de268da7c567669c3890b1bba2dd9de7518b544128040808c1886bf4c623afa3e2ffd9ba831bdd56b152d0391f8c588effe06bbc8908c13605e496e34312827ab5e5b2fb271fced1032af6b9277c8d5b5303dcfb83f3ab59a29356654d7bd391d5a47f3cafc952c8182660533f13d9996237b828c1dba6bd8bb897c0237f4222694de9f4152d29676db443728898e1e827d9fa036623a4eb6e369286201b26e3d562cbe0802f987c005ac72b31e3032962b69e58ebf605e1f4bdf15246bd9aad8804561aaed747614c7ef15d584c23d217fe4a918d95fe44889e1abd73fb120ef11825bcd86248cc03dfc66179ccb29b68ffe2c0d1bc44594af21316916aa95313ef39145f6268f268c8ae6b004e1d3532e777a1f52b5da8ad83380a4db846d3dd4a1b4c93ced31869b49f68e46c0d7fd8d87f86749947f30e667721d5cb85f20b2ee20d15928b027b1a5b07d79f206517ad811f2ed2090bd0d343aeada7ea364b6cdd696e5600f5c1e5735dd382a421d185704b4e9aa044f43e9238954e509e9feb517aa445f944449ddd25801e4ecbdb83e2ed4b47a467e8119f3f511b7583abcd03bba3f391b6b9ba76c30740118921f48ac145a09fd7527a1c828bb3ff2cb36c4b929581a419e358237481b4dd4ce0884e9598116a879a689d2fe49fab632636af55f243c906db04d734f565eb6b53d2adda69
#TRUST-RSA-SHA256 9ca414450448759a0f187a64fc8eaf6d7546b7f377e63c22dcd17342efaee0b8bcf6cf83c12cc4ee5767ab6ea1d6a86398aa0f81a61ef18dbe7f9007afe7f800e84922bd7727e4d3315e80df689dfd22f47ae0f35a4a4e8e2fa05462d93093ef4d549657e3fd7b4c54c3e465fc4b3a620b1f4ac8b45534bc9d2780e77ccac361003a8f59e378bb03ce7f56c224b9485409fa5752a9ba612a59d4e4ee115fd6135330bcd26fd0e336b199efbec6ea5dcdbaaae50ab2f5fa315d030ccccd5e1f069e21100e232a5dea1ea38ecf2a1907cdb1cafee9b8228ef6e04935fdc5d43a08dddb0bb5fa01d2e9547db19fb0b1c5886e2b9634fcef59eaece3e770959c42926c240b79782a945e570c8a0220a6e748004d2ae40895c6266b3ef35a8d5d9d3a75dbce4c857b7943a6cc39b6e3ab4704293e10a69ba1aaf47c0ffdd40c6112409015b9e1c72c2f1c2ba87e534c0ab1dc820388e3074b223ed1d3105833660423a8d35e4bbba3615b939cc2f2cf8549dfe3522bb13bbbef22145761332edd8f6119c2758f3e596ae6140d44942b8eda28a8871d9e486d67829435de04666f3d4d6a89b00285ccdfa6812ee9cb9417bc173f8ed6a8a682aef853b5b3616662180bd55bd3511859c13fe53a4201b05cad1e8b8decb79819313b12358cf78b90471de6051e51ca6484eacd9a1127314d875cd19d5f09495cb3c2074b5eeda3a3508d
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(215117);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/10");

  script_cve_id("CVE-2025-20185");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwk70547");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwk70559");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwk70574");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwk70590");
  script_xref(name:"CISCO-SA", value:"cisco-sa-esa-sma-wsa-multi-yKUJhS34");
  script_xref(name:"IAVA", value:"2025-A-0082");

  script_name(english:"Cisco Secure Email and Web Manager Privelege Escalation (cisco-sa-esa-sma-wsa-multi-yKUJhS34)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Secure Email and Web Manager is affected by a vulnerability.

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
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwk70547");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwk70559");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwk70574");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwk70590");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCwk70547, CSCwk70559, CSCwk70574, CSCwk70590");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:M/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-20185");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/02/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/02/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/07");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:cisco:secure_email_and_web_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:content_security_management_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:content_security_management_appliance");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_sma_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Content Security Management Appliance/DisplayVersion", "Host/AsyncOS/Cisco Content Security Management Appliance/Version");

  exit(0);
}


include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Content Security Management Appliance (SMA)');

var vuln_ranges = [
  {'min_ver' : '0.0', 'fix_ver' : '15.5.3.017'},
  {'min_ver' : '16.0', 'fix_ver' : '16.0.1.010'}
];

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_NOTE,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCwk70547, CSCwk70559, CSCwk70574, CSCwk70590',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
