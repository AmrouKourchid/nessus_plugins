#TRUSTED 57fd60c73aa642f616641e5815db884f6b2469f9194c0ce8af87d9f57bf9019ee470518bf59b801ce807b5f6acab200e8533bf7dec04e43beb683ca878d0442e19743fc67d6d97c54ca14998c7fe204e03dfa50547b51e42568235e278415b1256040c8ff1eb0cf01140de86c4c68d4acbf41aa30c9723bb948f652ae271350be0c8514ae507233e3f42887c772040d657d6218f427e1d0115a477da918f7dcbac25a61b6658c03532abd46a16b91416ae9d80c8bdc8cf752160dcf65bd8f5aa18d7f828f32cf81051efd0a4dbf59d3078ddaca7301223e55aa89fd35b9244571d676fb50ef204d75082da767b73b6e911b7f28c579da11af3c7c2806243b8f52ee608e6b9250c4a59b2fe3fd7751aafc88a656399354716e7d086bcc32326bad2f0cd95c7d99872a14c885df26d4f654feb338530e06244e520cbeffdf0399709bc84288575d52e6d3582123c77e35b02af5b648ef03042bd545337563af76b9966c06bdf1bde547a85428b6d96750a335c4de4ca117ead211396320bb635a65d483c959106b3c7d948187b97642b4651be5c2059b96b8a2b6f9e45183d2fb03830712f788d536a7723291459dd2613dc173819abf7c93ce58889b318fd0355e41105d023e12f8f33fa62e12c7e503cbe02ef2087100380e4930b6bf2435e7dcebe32f77cecb37fce0c862024a3af26056e4560a87a6c52f23e8881086807fe
#TRUST-RSA-SHA256 2a42a1edb0ff3759374db2709e91baee2f4354a8da75a2be874e353b8ff3a339233830f53cabca2d495ff1bf48172410b0a5ca701060bdbdeaf6fbee93fc885f16b19243c8b6406077e8969e6948a4a90228051b63cdf071acb5a05ded51dc82a4f6bc6c40865ec67bb7f6fca8e07a01798f1610775864975aa1974737802a3862dbdb2fbb07c34f9836abe8994f030da3ad19d3a07e0f07bd5eab551a8a501e4bb1ae6d98cd040c7e463e38d3f713bb289b1d4fd040fa70154c499dbd370af2ee481da8ab5d2b03afe91ab8f5fd7f9106f5c722194d2bc1df818b8823437fd1b608a1f0c4bd306224d7a10390ab35278b7dc1999990d2ee2b1aacc9b57ee219bac4056e39864b7af7615856fd2885603ee38ecd124b070286cbb650ab837737a90a3b248965aba3e090c2c29d222777851e2bcbb7e70dc7a87a1328fd24c3fd1ceb8695db7dac1988e77bc6b3a48fe1194366c80c05674c921df34e152474513a23b38b3acde0e84c63826c02184a2b8e8dcdf6dc80f4799c5016b6a0167bd998c2cad3e7ca7d40631e7eb12921212d141352b4b2b46311491c4d408a1a2f96e18a262405de1e4b87f9671787105d32914742a7774effb125f04e6a4ece19baa99d1bab45763ce536f0da33dec63ae73dbc7e8c93adcbc03ff915764db0743ca14331da012f8a38664fad0c29f52d112c753793b23fe27597edd0314b2dbfc1
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152974);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/28");

  script_cve_id("CVE-2021-1579");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw57164");
  script_xref(name:"CISCO-SA", value:"cisco-sa-capic-chvul-CKfGYBh8");
  script_xref(name:"IAVA", value:"2021-A-0403-S");

  script_name(english:"Cisco Application Policy Infrastructure Controller App Privilege Escalation (cisco-sa-capic-chvul-CKfGYBh8)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Application Policy Infrastructure Controller is affected by a privilege
 escalation vulnerability due to an insufficient role-based access control. An authenticated, remote attacker can 
 exploit this, by sending a specially crafted request, to gain administrative access with write privileges on the 
 system.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-capic-chvul-CKfGYBh8
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e6b0162b");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw57164");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvw57164");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1579");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/08/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:application_policy_infrastructure_controller");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_apic_version.nbin");
  script_require_keys("installed_sw/Cisco APIC Software");

  exit(0);
}

include('ccf.inc');
include('http.inc');

var app_name = 'Cisco APIC Software';
var port = get_http_port(default:443);

var product_info = cisco::get_product_info(name:app_name, port:port);

# Not checking GUI for workaround
if (report_paranoia < 2) 
  audit(AUDIT_POTENTIAL_VULN, app_name, product_info.version);

var vuln_ranges = [
  {'min_ver': '0.0', 'fix_ver': '3.2(10f)'},
  {'min_ver': '4.0', 'fix_ver': '4.2(7l)'},
  {'min_ver': '5.0', 'fix_ver': '5.2(2f)'}
];

var reporting = make_array(
  'port'     , port,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvw57164',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
