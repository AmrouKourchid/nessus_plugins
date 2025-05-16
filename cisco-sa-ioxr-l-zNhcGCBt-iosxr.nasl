#TRUSTED 993a0c92ed439c2283bed8e31bc1d66eec1f8f442953a198997f0ad16cd3653b703cac08758741a291536736a36d5dd59af01a2fc8bb903f239dcef22e47801a1a3a913af100bd9aed37bf7640473b63c5735811d8d8ce9eee8af0fe8daa6960d9b37229c84c05fd51ef7b96465ad5f34c55adc06e8b670915ca1e532c67f90395d3b3c136534b2a9db3a03589bb8a9644de3e01456034bcf3c0cd383adbf133cd350e4385aab08fcc0ac90bc0d6b16e9a4110fbb576609fc600929bbd38bad41061cb02051762443f48c7c72a53e8877d17b583ce10499a63dff0176b68b4f07809b747b0e0a8a33fc8637a7d4f7cee2524fee3bda4f038bb4f65b194fa5ee1ee9e4795043ee2ff6fe38099d87f7fc4bbb26226f04e9d19ae2afc3dd2e7f7796a23550ee4457f2ae318f6e646abbf5a1641f8441de4e9071397b099dc873b2402348c9a68397c7ca0127e599bf90a5912e1cbf5119b71e772072829b6a38daecfc65b7ef50c1d705d8c8a6fa6756f70f6520c43512baf44797e3488c4bcbc8438747a64c5b3c8143eb781b47335c75ec5d55852aca5253805f1f0a84d82be4b32b9e5535f756d2d12ec71b73337d705d5ac433ee123886d042320d794804515671d74f23e7b9e1e3f8dad2fe3242ad561e9fd8de9e8866997c725955459c6490381b43369487aed70b1eb33a9f38d305b4a11ed9a0e673ce7f72fccbf52d65c
#TRUST-RSA-SHA256 226226f4ae45c20b924e56899aa151b0b537a5133a62769c0c96afa4938e24f34e90f5544b4790c0d5eeccc5bf500efc4fb3e2bc21251e88ff22ca126a2cc504dbc8aa7d7f4e07c4fed01eaf18bc86912a00b695882b7d9ce096f071475bd81134c6acc6c015703a97a6e46613882ce850454eafdf130d0da442a6cc8dc8f3804b9251d7386265e37084fb253754ffb3e4df9f1aed842fc2a029bfb7af5eb5a004863c20125b9ad81cbfefb562634e41fd7df469c0f9159ad545206b03d20f8cf31930c88b8ba26b6a3f2049a186b0e96e5545edc11ed32c4dea22a5e378fb1887f8ab9bc9da6466fe55ec77b4c85504b82b36d6993dc83cab786b14706fc3f9ffff5af1222fc1f71fb9c4b0c83c09d43f81de49ca28c1d84ac23f4f08b7901fb4f63d0880b969a591c8b886bd25ce31d9e040ebbddf99b198896634befd879116ed57876e6b3047f63090ba71bd3d7ac5f3c461d9b200b09115042098386f2e5bd73cc5c075fdfdc912492903c170b738699b42bab3f49b81178272781bbca429cc4e77a6a14ec1c38d673a9e7a29ee54145a7d7eede9bad9ff86e81d77ce07209c23a7b8db53bd11a1e05e7542787df5d2fbeb3bf71b2c55b33424182283f734ea57218ae0bb85ad56937bdcbf247f82e48f9afa0a30c002ca0cae6acdbd6da4a0d7b7ba2f042baead0185a920ed5a0f6bb11d2e9251a5995bc76a31267426
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(147649);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/10");

  script_cve_id("CVE-2021-1136", "CVE-2021-1244");
  script_xref(name:"IAVA", value:"2021-A-0062-S");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr07463");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs70887");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ioxr-l-zNhcGCBt");

  script_name(english:"Cisco IOS XR Software for Cisco 8000 and NCS 540 Routers Image Verification Vulnerabilities (cisco-sa-ioxr-l-zNhcGCBt)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS XR Software is affected by multiple vulnerabilities that allow
an authenticated, local attacker to execute unsigned code during the boot process, as follows:

   - A vulnerability in the GRUB boot loader of Cisco NCS 540 Series Routers, only when running Cisco IOS XR NCS540L
     software images, and Cisco IOS XR Software for the Cisco 8000 Series Routers could allow an authenticated, local
     attacker to execute unsigned code during the boot process on an affected device. (CVE-2021-1136)

   - A vulnerability in the signing functions of ISO packaging of Cisco NCS 540 Series Routers, only when running Cisco
     IOS XR NCS540L software images, and Cisco IOS XR Software for the Cisco 8000 Series Routers could allow an
     authenticated, local attacker with administrator privileges to execute unsigned code during the installation of an
     ISO on an affected device. (CVE-2021-1244)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ioxr-l-zNhcGCBt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ee8a7f16");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr07463");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs70887");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvr07463 and CSCvs70887.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1244");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/11");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XR');

model = get_kb_item('CISCO/model');
if (empty_or_null(model))
  model = product_info['model'];
model = toupper(model);

workarounds = make_list();
workaround_params = {};

# 8000 Series Router
if (model =~ "8[0-9]{3}")
{
  vuln_ranges = [
    {'min_ver' : '7.0', 'fix_ver' : '7.0.14'},
    {'min_ver' : '7.2', 'fix_ver' : '7.2.1'}
  ];
# NCS 540
}
else if (model =~ "NCS\s?540")
{
  vuln_ranges = [
    {'min_ver' : '7.0', 'fix_ver' : '7.2.1'}
  ];

  // NCS540 running NCS540L software image
  // vuln if LNT in 'show version' output
  workarounds = make_list(CISCO_WORKAROUNDS['show_version']);
  workaround_params = {'pat' : 'LNT'};
}
else
{
  audit(AUDIT_HOST_NOT, 'an affected model');
}

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , "CSCvr07463, CSCvs70887"
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  workarounds:workarounds,
  workaround_params:workaround_params
);
