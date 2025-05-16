#TRUSTED 8a94a809441ac62068765adafb5fa052266a676633a8cb5227f3cd2b1a31d787ff15e1d351ea0644964930d90637bef608cb8065ec85aad09f10f061d1170bf7a9489b4466a6d73c56d4d6ce5f9e655d7d21807c59f5f3849e145c4b48690c39b0ebc2da1520a16627c2c7e7184f1e7f66293d6787614ab4a1b38b193fc4c98a7f171e44dd86df21c2a328cb9be6d04e59b2e56007706aa16c7fc51e032b02255d33672247368ba6f0bd8c417b5ad44daf70cf7c81ae0ef6068c38c83e3eb4c8b94da7f83fcfafe23bf731c97ac980d52feedec0767068e15d418ce9da02e53fccc431a9cb7bc222d10e09b320f52d802420a57b52733d56afb3283e05b4ad64e7fb4f6779b6ce9811f64f00fbdd65d79501be596e5a0a5acc989359f47761206b30b6395e0c0d10042b12b844d6bb78e0568bc9f2143941a18593412ab5e35d44cc0dc4e2d0714866143e2dfbd5990df0d5528c0077533ab5350203b2450c7e191be52c033add4941decb8c4598caaa0d1b66f3ba0f0b7957df90539591e091e00a8508c9d6c8d7c45c2373433c21832ea5b6c091931be70fb0d5fd41172cc4af9f3c6ae4004d7bba685d0a6e36b7933e6a32de4896d102b31d109b89b18e46d1a7267dc306844d71ce36bd3dccdc347fec5ac2e7cfaf4ffa992f110e7490b22e1867479cce07c1e9cc2654fdf1c348efdca94b6b01d81441c0e39043864b29
#TRUST-RSA-SHA256 68aa6263a004b35dd33ccb9f7827f458d05db40208bee6866e15b09e77213b6da9d07f60f99efc9e3d5532a06b296a143bc014371f64f94c3f403740076821c9e8cea8fdeeb7a617199fc6f49ddd74f09bff9777fa2ee590fbeebe7281c9386125d5beb2b03e1a055be255caf5a446ae52507fdc2a2c773b3dc097641382bff3d813cbee0be7b4aaa7d4f39b4b618cfbbfffc2b6725ffc3290c275692ed9ada93ca2cad9117ff48bf6634b6983bb53724f42923385de52d039d8b28ba39a0b0104d151f7f9f07e4fbc450566e9bbcd5c53b1aee54287a88ba22536fec2c05a78ac5722b34c8e8f63b34b56519eb699ddab029873d9b0a98315341c9f5f79981a6ed0febf90e3afdf079607801a1b5824cb46e594d5f55f2cbaad9c355cc54c7b13d06f56502118d279d8a60640e42420819eb7af6d8544d9003d6d40f5780e151f463dd16dcc729b16ac3fa6f89ae0cebeaba95cd873fc8b6b096ca9d32c055ed1d05510996cbc5153e81c0a6b5236234d8e430b69a89711c599e92315745fdf0f6512871a3b3fac980acfd98e3af78e6ca77c6dfcccc4581297926a6a395f9abbd3c2280d57fb9f37a313b81fd85678993522e0c42a1258b6fa95c2e3db9629753fbc24e56c660880b4df3b675dcd0d178db3ac6aecc47e7751b207f5a1cee308bdb8cd09d401fa096eaf153f88e550a17ca19637ca8fb8fda17c886f733575
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(126103);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/15");

  script_cve_id("CVE-2018-15440", "CVE-2018-15463");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvm71860");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvm79609");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190109-ise-multi-xss");

  script_name(english:"Cisco Identity Services Engine Multiple Cross-Site Scripting Vulnerabilities (cisco-sa-20190109-ise-multi-xss)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Identity Services Engine
Software is affected by multiple cross-site scripting vulnerabilities.
This could  allow an unauthenticated, remote attacker to conduct a 
stored cross-site scripting (XSS) attack or a reflected  cross-site
scripting (XSS) attack against a user of the  web-based management
interface of an affected device. 

Please see the included Cisco BIDs and Cisco Security Advisory for
more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190109-ise-multi-xss
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3a6a291e");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvm71860");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvm79609");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs
CSCvm71860 and CSCvm79609.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-15463");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/21");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine_software");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ise_detect.nbin");
  script_require_keys("Host/Cisco/ISE/version", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("cisco_workarounds.inc");
include("ccf.inc");

product_info = cisco::get_product_info(name:"Cisco Identity Services Engine Software");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

vuln_ranges = [
  { 'min_ver' : '2.2.0', 'fix_ver' : '2.2.0.470' },
  { 'min_ver' : '2.3.0', 'fix_ver' : '2.3.0.298' },
  { 'min_ver' : '2.4.0', 'fix_ver' : '2.4.0.357' }
];

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

# ISE version doesn't change when patches are installed, so even if
# they are on the proper version we have to double check patch level
required_patch = '';
if      (product_info['version'] =~ "^2\.2\.0($|[^0-9])") required_patch = '13';
else if (product_info['version'] =~ "^2\.3\.0($|[^0-9])") required_patch = '6';
else if (product_info['version'] =~ "^2\.4\.0($|[^0-9])") required_patch = '6';

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvm71860, CSCvm79609',
  'fix'      , 'See advisory',
  'xss'      , TRUE
);

# uses required_patch parameters set by above version ranges
cisco::check_and_report(product_info:product_info, reporting:reporting, workarounds:workarounds, workaround_params:workaround_params, vuln_ranges:vuln_ranges, required_patch:required_patch);
