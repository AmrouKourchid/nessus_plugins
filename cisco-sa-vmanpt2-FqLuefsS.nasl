#TRUSTED 5066c81e8785ef8f5ca85a52e727e7e774f6077ea6ecfee78f89d98cbd9fbea1401973239ee284ee1d5c268f546f5482be57a696faaa355371ccc99ffae26eb5ad94dba7cefcfe8403edde69e8bc20d46291ff79e4438ee3a0fd3d208917ee767a8129458aa38d08b0c8b0a31bb750fef784b7494c13f5cd457ec3bc0fa649467134db43066ace76690ebad43dd9279105cbe3d5f69b2e6c69131638e7a182b7d834fb58f6a004575252d17dce8e6998d7f514b1ebeb004dad80d7b191099a182ca00bd15c982c823d6798777ffccaab60f27d293828049fe4194290cfa1268a705db5056e0fd9c6d214ef28a96f13b64c09bd8622ae2e97ce8b1211cb3fc3ec4a40dabfae8946b7dcd426f3fadd9c59b88b2e4255621525437e8b725e54f7c8e28726f292dbec18f923a02ad9a2c9aa6e24ea5d5fb322a3d4090513611693f7d59c2a52059869045b139f553eeba629fca0d00fac9e845336624b52d29a8a4d1d8fba4b9564ae340824d36d55fff73544d0770693698f701e6828b7e38e9707b0180074053d4e2727b5083fecd2c80a5188fbc86087fe829235e30a944199ad7927a5be889f3fce94d2a6f8a5d0e50a665560fc0c689848a097b3b3ff8bd14c3e27ce375a23a343ed83988bd31b37aed951d29eb43ca3a91b26076b5faeaa1b15d754eeb71b3fcfb01347dc27ffe63e78b73ab45c066249895f950ab6d63f0b
#TRUST-RSA-SHA256 a5cf8b5792198d058258b635aeca9710421285a2c841ad0626e47809cc12e33b0f01ab9064a23e1da48bba6e8a3439474ab5fb6566e9f835648612c57412597df44c105d693a8d1d3795d43d45027f839e970edb231d1520aca6a4dc3c4e7130068bad0c7cba6f334bf95a6a5375984b38865399fc649451cba3eb8ddb83542f8d1e864bac1adb49b4ce2369ebc907c8b348219d5f1a31d8d04112145627b15a4ace8019d0d573580e0ccedb4b802851e29af3d96569489e11ce012c4d298cd1c9b78cd89b73e033e2e97155a35d31ea59226f6e835dd183a685ae163863f9d9fe733f67e9a858df139dcfe36e098839292e7785e5e7e9ddd90c54b36185dcd51d6f6875b6ca42c61e266fa71e1864032eb7edbf8fd2b3af5ad1a2fba4c85a9eef58dfe1d7b9716e060f2e42e265e3cf54aba5cef6264f9e4dd9919761af4176049652ea9dfaa330a51b54edde371011bcfcdb49202da9bc09e52f811e85fe405cdeb308b32809c4b84488be757e0e4c8a3e808a06a705752218f13635e995fcb2f8c4a2e690fffbac09f2345aa2cfe1e9c45e4d9cea3aa7bd8a8a6fcb1b827a1c5df4ce5745f1e42ec2c1fe38ad9e7dafc405bc51d003b20f89b82f8e8e7a14945ab2dcbd741e1066bd8695f67dabad0b7957e74aa07984fd66f451418548ee464e2433ee0826ca6baf65734a139cd76e109037203a24167348f0982ae84dac
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(145551);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/25");

  script_cve_id("CVE-2020-26065");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv03658");
  script_xref(name:"CISCO-SA", value:"cisco-sa-vmanpt2-FqLuefsS");
  script_xref(name:"IAVA", value:"2020-A-0509");

  script_name(english:"Cisco SD-WAN vManage Software Path Traversal (cisco-sa-vmanpt2-FqLuefsS)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN vManage is affected by a path traversal vulnerability due to
insufficient validation of HTTP requests. An authenticated, remote attacker can exploit this, by sending a crafted HTTP
request that contains directory traversal character sequences, to conduct path traversal attacks and obtain read access
to sensitive files on the affected system.

Please see the included Cisco BID and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-vmanpt2-FqLuefsS
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3d2f53d8");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv03658");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvv03658");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-26065");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(22);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:sd-wan_vmanage");
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

if ('vmanage' >!< tolower(product_info['model']))
  audit(AUDIT_HOST_NOT, 'an affected model');

vuln_ranges = [
  { 'min_ver':'0', 'fix_ver':'20.1.2' }
];

#20.1.12 is between 20.1.1 and 20.1.2
version_list=make_list(
  '20.1.12'
);

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvv03658',
  'fix'      , 'See vendor advisory',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list,
  vuln_ranges:vuln_ranges
);
