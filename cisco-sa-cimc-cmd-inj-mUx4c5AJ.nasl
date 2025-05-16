#TRUSTED 9ec7ff018558d0a1d36be71f84876be873936366e57c0d6d41ff996102fd063116d06fd18e72a452ebe232f46389ccc36ccd9a3202c68899f97669670bf1507fb28a1ba6efaccfa36a3e1b3059763c82efce5cb920d047201db6a43b0674f7d303c38e898bc56ca8379c138a407d3faed65361aa3c7e87e4f088763c3a53c6d6168464ff85edaf47e3eef05fd5082b0db3a4297d1aba061918c3bd3dfc672443b6c02d0a1564683a41945395453c7e9b5da9a68804a19a648686faad3207360b4e02228c8b079fa6af1e24d7aed6a47e0c3d5c2e819992f8fd336a7f1bc1c4fc376132090016136c7c6dff8c499522cb3d20dfd2d8c682989a7a0d831fc57e6f78c8879a9a3f7a84ff541bcc327293a3fa4146970fdf1f8c4a57f467e2d87a827f020f7b06884a77c372d54890dd7a3250dbf4bcc8399f507e2946c1a45f37c22e5dbac1e5c0ecd73b894df1e3b71a034f1afad90b128593402077b7b7fcf2779954177f31b7eacb7f949147d9aca6f691dfc4f715d3ad138ab1ef5744b7d3a232c1cab36bbf99fa988aa5c04c49d55ae6b07a49d8bcb2079de1d19a5272d4b44a51b110c1790dadcdc369900f6e9a9535aa85e5655b411f001e8dbdbd5cc0eda73a12a1c33afd4f9a61cbd46bde883a3fb0f1367bc13398b88ce0cb893306241891265056a401bc9afc443dc8b8e899115df078d45bf29d16280fcda7a029b8
#TRUST-RSA-SHA256 8f28bba1e7a9a782d0b1168beb9515547bb8d7b3939f1fe5bec65abbb651bd46d8c66ce02e607b91808393c46fefa0b21d8b0dd7e8a209373f46d764412f38b18222cfdf415b5d18c78bdfdcbcc42d18ad97631c4be26b6f7e764b4614a4ef1c33b92efc65740bd5a624d9af3a44511ca8861af82949829af422415a9d9e111d4b2f2fdbd1e50400c11c904d7bc907e8d5cf4d091480bab27e30a5dc24ff197c4f75edeae16883b36f801057e819d05039c03f4e0ed3fb225851615d4be69ac680a06aab67bb3ff7f7a1ba447cfdc0d6ab6b48de2c8ed3be3cbbd020623a3f5ee24bd447d4cc4dda68f9adef78db992e7ceb57c31a6f3ac27ea2388aa02a01a9ad03aff62f1db1c6d32fa6ad49df6ca80a7d183100a189895f3b9d4621f4f3eb64ab879c059d1ba23711849d63363eca4bc944359850957a4f631aa29cb5d79d6da066fc439b0282b7502887b9ede229b9b52f2bd3e81786a50259b8fbee564756ea83a618a0d18f86e4cd4621d66bc693a859d9c1bbd48b9619301fc8bb58cb27b6f83f017bcbd9500c19aabf470610d3e1c13681e93e5b1e7a7e983002a7f45609c38775b0000e33a5c144d1ffd36727ea1f03d5afb3a6df153230b97c13e4ec6d2d102ba269a7aed243b2b4ffb56184b4500abaca00d634da3b402d7fe881aa0a4a685f9ad481ee48baac2456971614ca0e7b49b44040ece807653d0d4791
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(193586);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/15");

  script_cve_id("CVE-2024-20295");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwi10842");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwi12864");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwi29799");
  script_xref(name:"CISCO-SA", value:"cisco-sa-cimc-cmd-inj-mUx4c5AJ");
  script_xref(name:"IAVA", value:"2024-A-0250");

  script_name(english:"Cisco Integrated Management Controller CLI Command Injection (cisco-sa-cimc-cmd-inj-mUx4c5AJ)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Integrated Management Controller CLI is affected by a
command injection vulnerability. Due to insufficient validation of user-supplied input, the vulnerability could allow an
authenticated, local attacker to perform command injection attacks on the underlying operating system and elevate 
privileges to root. To exploit this vulnerability, the attacker must have read-only or higher privileges on an affected
device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cimc-cmd-inj-mUx4c5AJ
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b2ac5fad");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwi10842");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwi12864");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwi29799");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCwi10842, CSCwi12864, CSCwi29799");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20295");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(78);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/19");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:integrated_management_controller");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_imc_detect.nbin");
  script_require_keys("Host/Cisco/CIMC/version", "Host/Cisco/CIMC/model");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Unified Computing System (Management Software)');

var model = toupper(product_info.model);

if (empty_or_null(model) ||
 (model !~ "ENCS5\d+" && model !~ "C83\d+[\s-]UCPE" && model !~ "E\d+[SD]" && model !~ "C\d+[\s-]?M[4567]")) 
    audit(AUDIT_HOST_NOT, 'an affected model');

var vuln_ranges = [];

# 5000 Series ENCS
# Catalyst 8300 Series Edge uCPE
if (model =~ "ENCS5\d+" || model =~ "C83\d+[\s-]UCPE")
  vuln_ranges = [
    {'min_ver': '0.0', 'fix_ver': '4.14.1'}
  ];

# C-Series M4, M5, M6, M7
if (model =~ "C\d+[\s-]?M[4567]")
{
  if ("M4" >< model)
    vuln_ranges = [
      {'min_ver': '0.0', 'fix_ver': '4.1(2m)'}
    ];
  else if ("M5" >< model)
    vuln_ranges = [
      {'min_ver': '0.0', 'fix_ver': '4.1(3m)'},
      {'min_ver': '4.2', 'fix_ver': '4.2(3j)'},
      {'min_ver': '4.3', 'fix_ver': '4.3(2.240002)'}
    ];
  else if ("M6" >< model)
    vuln_ranges = [
      {'min_ver': '4.2', 'fix_ver': '4.2(3j)'},
      {'min_ver': '4.3', 'fix_ver': '4.3(2.240002)'}
    ];
  else if ("M7" >< model)
    vuln_ranges = [
      {'min_ver': '4.3', 'fix_ver': '4.3(2.240002)'}
    ];
}

# E-Series M2, M3, M6
if (model =~ "E\d+[SD]")
{
  if (model =~ "M[23]|E140S|E160D|E180D|E160S|E1120D")
    vuln_ranges = [
      {'min_ver': '0.0', 'fix_ver': '3.2.15'}
    ];
  else if (model =~ "M6|E1100D")
    vuln_ranges = [
      {'min_ver': '4.12', 'fix_ver': '4.12.2'}
    ];
}

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_WARNING,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCwi10842, CSCwi12864, CSCwi29799',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
