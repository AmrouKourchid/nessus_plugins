#TRUSTED 75e9b37e4deb7e096500c96dcb28855b5bb05c110f3a05f480ba0f8f22447d7628295ab9b98e05e6ba5613fadcc34c529b7d3796f9eaa02840c06967782b641c5dd49ab5b19925e3eef2e86d12667e4187ab48a2629e38737ab5e14433705c3a5fd15ab3a9e7e5a3a58fec9e09ed6bc29ba5c83035987d5be261a3e21fadf5617e58fb7236dfd148bf41a2cd672e6fb7af1c5bd3687d77bfa4efa5e2eb6fe32c4a369a8262e622014a0d73ed69e5198a0fd9d61d367a01626570560b8e264d8c80eb608245566b8bcc840f8ecf6e6ea817ca903074b35ca4c0942f349f006c714543c6e869f61b2299cbc96d54050ef903a47469d9f8cff1769f433f8e7099a7db00cdebfd07dcfcf70b476e3b07bf1266d61935ea3dafdf07705db488bc0aede02e8efc24b6f1218b2930bf9541ecc4bca82ef94b6628787231b07c8bbf25bd82eb3d7ea5ea71474d625ede7b779ecb4e7725812e29c26ce73e3cbe0d18049962ae7a24579af489a1647024e50b00037d6a6e632ccf2e490e782516a393d14ed8dccde4f35e35231bc9570fbe0cd5c4c7be96083bc240f9e171ca5ad58b33690c39679656f055ca10643f42554cf005749045feef0c00b2921409ca31d65894df89c0bf5a68171beefd1f7d86bef1367069043db886c56e3978ec706c9c1a1f0d7222f5e31f76ed99ca7e88931a9fdecc68109df42e96d2200c764c03da5bf0
#TRUST-RSA-SHA256 30f3f90917bd2da1276e21ba5bca868dea7d6eb1b1d07f5135b983b596e76860eec14f0d026f1b30df1cb5935531bae759e823afdab5cb70a94cfde74784fa992b7dcbfe0df7278a1486ac9e8a4432beca2ec10935b64204be870c6d9c6aceac097ad4f86d110cd80debf516756815bd73f144f51eee52a6558418a6b79efd1de99ac926b95d9029308231aae6094aab9421bc78462fa941cb4f94ae7ebb46d3c8af50d1acf6571f248e2c3ce0f4ab7caf3aaf47c7761af1d4ec0045211c88ac9549afa1365e9ab03c6de0e3c5e4acc82ded340686635da95f161309389fd0118fe031ece60b013aff0c2720e5a2100cf2ffea7349038d35599ed38dc8363bd589836b73dee99d1a21018c7ed6f30ce957d0ab71cd969f57f95d6767c4005e872cab94daf4995c98e3bad80ec3710d8c95b04229e54dd874361be6bf60bc141f649e345b2b9234863b71ab119d247f6ee1e5d723e735b8b3308f5b7fe8f4cd19598cc40ec9296d75889293e511d745372adba1dffe2c6fe8893ab1a088dd63e58367683771d63fb94157e8fae2c6fd2be6c5bd350da52abc9ae2aa2a9bb586956aa58047e9e710ae60d1680d2f2ae3e3f6a062d8b51e5372ad86fdf88d292ccd44cd03b4b7b8bc73b5ce60d21ff50f23ac75666926823951b568cb5ac44cb22415a44acdfa181511cf994a6bab9e8f8c3430585b6b75961e501961ba9f6d3b3d
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(137852);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/05");

  script_cve_id(
    "CVE-2020-3286",
    "CVE-2020-3287",
    "CVE-2020-3288",
    "CVE-2020-3289",
    "CVE-2020-3290",
    "CVE-2020-3291",
    "CVE-2020-3292",
    "CVE-2020-3293",
    "CVE-2020-3294",
    "CVE-2020-3295",
    "CVE-2020-3296"
  );
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt26705");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt29414");
  script_xref(name:"CISCO-SA", value:"cisco-sa-rv-routers-stack-vUxHmnNz");
  script_xref(name:"IAVA", value:"2020-A-0274");

  script_name(english:"Cisco Small Business RV Series Routers Multiple Vulnerabilities (cisco-sa-rv-routers-stack-vUxHmnNz)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Small Business RV Series Router Firmware is affected by multiple 
  remote code execution vulnerabilities in its web-based management interface due to insufficient boundary restrictions
  on user-supplied input. An authenticated, remote attacker can exploit these to execute arbitrary commands on an 
  affected host. 
  
  Please see the included Cisco BIDs and Cisco Security Advisory for more information.
  
  Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported 
  version");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-rv-routers-stack-vUxHmnNz
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6d21c4b0");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt26705");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt29414");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvt26705, CSCvt29414");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3296");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:cisco:small_business_rv_series_router_firmware");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_small_business_detect.nasl", "cisco_rv_webui_detect.nbin");
  script_require_keys("Cisco/Small_Business_Router/Version", "Cisco/Small_Business_Router/Model");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

product_info = cisco::get_product_info(name:'Cisco Small Business Series Router Firmware');

vuln_ranges = [
  {'min_ver':'1.0.0.0', 'fix_ver':'1.5.1.11'},
  {'min_ver':'4.0.0.0', 'fix_ver':'4.2.3.14'},
];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvt26705, CSCvt29414',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  models:make_list('RV016', 'RV042', 'RV042G', 'RV082', 'RV320', 'RV325')
);
