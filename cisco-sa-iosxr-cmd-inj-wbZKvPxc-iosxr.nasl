#TRUSTED 4b7073d51356fa655eee96d63cbd942f82749fbc2c02e229b775611f8ab0ac576620d748c88454066df3c0fcfd7b02e98a458d75391da764e3bb331c88a902f7d6b385516f4e897c6831208a07ef6b9246708db2ab69075aa77eda7a006166355e7dfccf6a242eae22dc5a3e5cd822e0f561d28c3633e9ad073f52e0702e76d71844bbe2a2bfbdfd219c8dec826fa79d4819325dc937cfc694be4940a5ad87478fa2cde413730c598bd36aa697f53b3591931c078a5680476d4596c04e35927214576085f0229a9aedcb0283aee0f576fd168ae1cbdc12fb24a0fd1ff7ba23605fff2982187a99887064f11b841bf480b3f74fd7ce011376b21a64f59af6817d7f47396eff858f12b57827c510dc99850ee3186297d1a69c7419afc2a857c0338ffd648cd2d272c16c8fc6fadeeebc8e8c6f50fa91d6590444203e86cc6029222a28d8e5b811d1be2a9ac0ea2bc9e6296154a75e6ac0e3a0e6f2e1f2cb47724c9c2707d893f5510091785b0d8446a47a7455e1d64ea319769195ae6d220e23683aa911603782eeb32bc0aacee7843978b5dcc9d3640be00c670af285cf2f2607781e82a068ff82a90ed82b0484f5fd483013d92ef363010b85ba691860e7bf5f385f5bef017e71e7146498e320caaffbc6c1a6fe10e827a0ced3f2127923d043f9d4e5a08f8155b8096cb6c093ae7b0085884fffed0f2f73ec8a3f2a938d2b3c
#TRUST-RSA-SHA256 2dde49954f6448c3b33faf736a8dbd177cf2052274777ad27e92d6d0dad07da6a4628c023418cdd35895f1a31e15d49aa2e9b30ea5b4852ffd419483be1fd1e82192884833931bad87739de2be30300311e49929d8f038285bb49685922fb051a1647096e51f2c82b926b2c8fb6fd361c30ee61680d0efbdefece3f6a2be4d141dd8323bd3b3f748ebd8ffef0360663daf94d14343c7fa76b8ca6277671592947fb73239b7463af69d7ff537497cd585ae781c47f1ef72729d6d2a1b211fcead7257dc2eef058a487489094965e12b5227beb8c428442e85d94984df46927407c5a112fe070354a6295ba6da61e487d463c7d4cd22b3d3406ca12b36c3e8d5e688827ee316d16aefa4f9803532c6f1d8fdbbedd3e4bf5fc6f4b466ec224a425b1c7d10495423f4a242692b092447446149cceb1156d75abd7581386c9d3fc4f595735faf674fd16e1a6b6d9710251b543c3d70c4fbc1f03d9fe99cc9c9dde9920051f1de4098a30cba95ebfb0ea0b19fc9a78a3d076d325e2893846474f7217710303768aa500980282b46392b381f84013da1a6ba863606c37230980fcc4c2f9f1c229b37ad66ce6c72693ff424f7a960037f221925a40e1e8541c3009f084b0f330a578fc4f63e69335ef6cd2d1e2e37199940399658db6806ae588ed21abbebb29e406d6a263259323dc6e169b3a0b2074647c03e952a1c9e353e582dd7ff
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153209);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/12/01");

  script_cve_id("CVE-2021-34721", "CVE-2021-34722");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvx48001");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvx48002");
  script_xref(name:"CISCO-SA", value:"cisco-sa-iosxr-cmd-inj-wbZKvPxc");

  script_name(english:"Cisco IOS XR Software Command Injection (cisco-sa-iosxr-cmd-inj-wbZKvPxc)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XR is affected by multiple command injection vulnerabilities that
allow an authenticated, local attacker to gain access to the underlying root shell of an affected device and execute
arbitrary commands with root privileges.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxr-cmd-inj-wbZKvPxc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?00664814");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74637");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvx48001");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvx48002");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvx48001, CSCvx48002");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-34722");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(78, 88);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/10");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XR');

var vuln_ranges = [
 {'min_ver': '0.0.0', 'fix_ver': '7.3.2'}
];

var workarounds, workaround_params, cmds;
# Workaround check needed for versions < 7.1.1 to show CVE-2021-34721
if (ver_compare(ver:product_info['version'], fix:'7.1.1', strict:FALSE) < 0)
{
  workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
  workaround_params = WORKAROUND_CONFIG['xml_agent'];
  cmds = make_list('show running-config');
}

var reporting = make_array(
  'port' , product_info['port'],
  'severity' , SECURITY_HOLE,
  'bug_id'   , 'CSCvx48001, CSCvx48002',
  'version'  , product_info['version']
);

if (max_index(cmds) > 0)
  reporting['cmds'] = cmds;

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
