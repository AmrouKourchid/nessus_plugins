#TRUSTED 6c5c69cda4212328d971fbbe5be73c17a657ddc0f4cd5d85ab0e3156ea681b5ae1b8d188139b68a498a9d1f6f07824305c2bd50500248d3161a6196045873d2f8a09d1969f70ee4fb31c3c808a82ca37c2f09d5cef68897333b300acd07d61f4dfe94a0f6ce983fe8657422d4311607c0c9d405e64728b34ee286c8a4b3a8c51abcc357e83841b6d5cd798ebef59d9df1b26a86d7e7de1dd9dc087bdbd8ebd458f2053339d6e6814cee9f43c96faa46190561f5284ba17aa91b05196c6a5ae47f0c167db7381c614bce9fba5305053b60f7a464cd5dbc9aaf9ad409c1153cce00749492d96f8c36e21c5199815651ffe0aa579bec33016b1428778ce8cb70874a36d11fc7ddc67972befdc1fb5aa8adade0e8225a632a23de9e0e874cf1f0da3649b7b38e631f23eabe7b9e92e08d307f6fd3bd312adaeda4e6f09a1042496749aac6f0e9816ee9ed8fba2b39d417b2838e4f999df344a9b88fb2b8670d6271634779dd1c8a5b24d0c5ad58596837fbd9d87281e06226e85fe0e27fcc04b94cddfabf6468435c675dedda3c4b43cc7803b5b2cc773acdf69d0ead0a29d68a9ef34707c47ed5f9d5713a809839a194789b1ea13a52e062c956408db3a1f69d548211ebcb3f51a785d01b0775ad1082a0ffbd070a43e9ed2abe72a8dfec453ca4a63f02cb702c3f3c472d0d250f16e67b2be73c67989f3918bc607c0a2faf22c1b
#TRUST-RSA-SHA256 2ab4255e81173de4884c761b0c21a71d4bafe1064a0bd5d021bb32de6f064bd25f0d4007c59018daae255b241bf31011afe65cc7748d05dc4332a15770e8c0b2d8b4b60a8f78ab0a38006094f4195e2008136d3bc926ca5cdd264e2c34829f33ce6bcc0c07f4706dcdd241d17129ae882d200fb1e33b1830a5bc30af09579fa619f54c16b481dedf606d9e9cba09d1fb86e749677b7d908af227d31d86ab4b6384e81dd5385c4981e3159b581d82a2c3f955946be90e8c6155267e42043404f7472336f91ca8dd8925b9625ad15e48c5056b030d435126762b5a568279cacef2bc63b1529bfaced5400cf8e5dfa435874219b4d9aa5035b0f3a5f87c124b8ae857e3aef40e51c6dd0cb1ffb1000c423cca221ce5b81a0c738638fe51f61e46eab78e744f2e9f418ccb560f9fe098c4f07d93740602df905d420f3d19e407b97749c4fb8626a1b97e8edf07498eb4efbeffb5a6676e3bc2a6fa3a555435334148f05e1a79bed0b29474cf78c6a447c7f58afa57e3f91dff4476c24626b39bd06ba9145a06b032b450d85d4b92ec5665c4541df4e0cc50a01f45457ffbff4adb7ab24dc5e903ba0f64c648cde7d16048d1e88871782c645c8ba75b2355efcf82525b2f68e9977ce6568f255f3c515b672e3ba72da291dbfe588474f79ff1632dedfdab2cd5ab9de5dba0d21f6cac0823ce378ed901a8988fd7382c3e60ff63a502
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(210597);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/06");

  script_cve_id("CVE-2024-20504");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwj72825");
  script_xref(name:"CISCO-SA", value:"cisco-sa-esa-wsa-sma-xss-zYm3f49n");
  script_xref(name:"IAVA", value:"2024-A-0713-S");

  script_name(english:"Cisco Secure Email and Web Manager XSS (cisco-sa-esa-wsa-sma-xss-zYm3f49n)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Secure Email and Web Manager is affected by a vulnerability.

  - A vulnerability in the web-based management interface of Cisco AsyncOS Software for Cisco Secure Email and
    Web Manager, Secure Email Gateway, and Secure Web Appliance could allow an authenticated, remote attacker
    to conduct a stored cross-site scripting (XSS) attack against a user of the interface. This vulnerability
    is due to insufficient validation of user input. An attacker could exploit this vulnerability by
    persuading a user of an affected interface to click a crafted link. A successful exploit could allow the
    attacker to execute arbitrary script code in the context of the affected interface or access sensitive,
    browser-based information. (CVE-2024-20504)

Please see the included Cisco BID and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-esa-wsa-sma-xss-zYm3f49n
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?18760d58");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwj72825");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCwj72825");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20504");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(80);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/11/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/11/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/08");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:cisco:secure_email_and_web_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:content_security_management_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:content_security_management_appliance");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_sma_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Content Security Management Appliance/DisplayVersion", "Host/AsyncOS/Cisco Content Security Management Appliance/Version");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Content Security Management Appliance (SMA)');

var vuln_ranges = [
  {'min_ver' : '0.0', 'fix_ver' : '15.5.99999'}, # 15.5 and earlier "Migrate to a fixed release"
  {'min_ver' : '16.0', 'fix_ver' : '16.0.0.195'}
];

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_WARNING,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCwj72825',
  'disable_caveat', TRUE,
  'fix'           , '16.0.0-195',
  'xss'           , TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
