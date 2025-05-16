#TRUSTED 5731de904e3666aa0c509d509fe8049a3ca88781dedcaed17a020a1158c9315ab9c38169cca7d190372c29f3f66a0555fabe00f2e9127288b0887fe9dd77ba057172422f07921f1e6865daef5f741fa62d7dbef6eae21a84a45098bd11cff93417a87d76b65b910bd0a408355ad2b8aed1256e9dd5ba896f10cfd5897ba23764ca16203c37435c5537e318837691c40f73223778ad3cd37c2dea3ce34e2a8be39e5e47791ced7e99136bf69f26809924ad76cc3aa1ef18d453ec5d10af50dba07387449ea538fd84af859b1428908e648c40fe1a14f10d98137729197de26bbcb44cda05d077e10633292f486e3d77b9b911ce419a2d6de12a8734124fcb230a29a96d2d44f43e631d81a0e5f70a324e69b3cd2ccd6c7f363a644a21c6a29142da2caf0318a984f6023faf19c6c25384ae45d68e3f7d878f8d1a81be9eeaf55926c7f62189f2c14a0d1a1d5b85cf4ba233e1bc2cec280cf57d18a47f6767ce0d1422ed7d1ab6043275b451e5072bd4c8816b9773391a8f8953c37dd17be0c68690af5ae2d6144019844e8fa13188759a0d68a1ed046cd95352d1165ed0d534f6fa1ce560fccb17c095140b04d1dd7d490811ee7d61ee70802af187aac206984b69086abb0c8d44b0942503ccc718154a07cdf2508969b61fe3c8ed3a8bb38198bbc577f709c0dd36161466edef9a9b6eee5ad3d98b0ba528b678f72ba3c1a980
#TRUST-RSA-SHA256 1d0a00b19988415722f383e8fec3be7a9d4684a64d21baf27f454f9937b5e962c79d74d8aac4ecd3f248d6d6781b4bd4a97f61d821f2ca4691f00ddb5a0116e33b1282a4d6a5c1425a5b14bbd60b4c04a0f4d76a8d884bd1d9ce1813cf619691e748d7b94e23a6c7e90bf3bed4b763ebe9b92ced526a7c86700b3305aab29d88e9808e125afcec8c4f1af0242dcb2eea2e29ca299bb0239683145cf5e30121db13cc88d4d8531ad77e4b634a623d462bc4133db1dd6f81483335e4b790268afe07a2beef2f6eb029f1500d218926f6fb0fb0a3f37d3f251f0a0796063bed0152f98f01f5e68ada71f232640881d41a555362ed76a14e0c0d206fe2c9b82f4d92446f570872ac60b4df6e2545178879d7e4f106987289d92f975521e66be41092387efc5ee8f6bd0e1d874d9018fff45447de7e9ace6cacd85af80ae2146f1604aa06e4089ed493aa89a1237f013c2defe618dfa57a14ea910fea87623fbf24f3014fcc0054c8fdf65838bf83d72b882ab60013ca7515736069b7dd293f870a5f05b69d65bee79176cb4899cb613cf89ebfef7d6218fa614ebf91803093dca4991a99828fb38df6b918a407938a1c463183c6d9b13c4062cf163f7805c9fe623be4b945427e9b53bc47793e4872d075d4ecb35130c0764f73e633c178d2a7b87a6b283925c973758de0ed0b4cde29b18c0580efc2c79a3aefe3314cd804f46757
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(215123);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/06");

  script_cve_id("CVE-2025-20205");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwj04202");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ise-xss-42tgsdMG");
  script_xref(name:"IAVA", value:"2024-A-0710");

  script_name(english:"Cisco Identity Services Engine Stored XSS (cisco-sa-ise-xss-42tgsdMG)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Identity Services Engine Stored Cross-Site Scripting Vulnerabilities is
affected by a vulnerability:

  - A vulnerability in the web-based management interface of Cisco Identity Services Engine (ISE) could allow
    an authenticated, remote attacker to conduct cross-site scripting (XSS) attacks against a user of the
    interface. This vulnerability is due to insufficient validation of user-supplied input by the web-
    based management interface of an affected system. An attacker could exploit this vulnerability by
    injecting malicious code into specific pages of the interface. A successful exploit could allow the
    attacker to execute arbitrary script code in the context of the affected interface or access sensitive,
    browser-based information. To exploit this vulnerability, the attacker must have valid administrative
    credentials. (CVE-2025-20205)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-xss-42tgsdMG
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e2070210");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwk32089");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCwk32089");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:M/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-20205");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/02/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/02/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ise_detect.nbin");
  script_require_keys("Host/Cisco/ISE/version");

  exit(0);
}

include('ccf.inc');
include('cisco_ise_func.inc');

var product_info = cisco::get_product_info(name:'Cisco Identity Services Engine Software');

# the 4th segement is not relevant in Cisco ISE
product_info = strip_fourth_segment(product_info:product_info);

var vuln_ranges = [
  {'min_ver':'3.0', 'fix_ver':'3.2', required_patch:'7'},
  {'min_ver':'3.3', 'fix_ver':'3.3', required_patch:'4'},
  {'min_ver':'3.4', 'fix_ver':'3.4', required_patch:'1'},
];

var required_patch = get_required_patch(vuln_ranges:vuln_ranges, version:product_info['version']);

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_WARNING,
  'version'       , product_info['version'],
  'flags'         , {'xss':TRUE},
  'bug_id'        , 'CSCwk32089',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  required_patch:required_patch
);
