#TRUSTED 685d247a160bb2edf6beef09ca296b0ec4652fbbfc10c90a906937ce9a819e2cedc9f4b87f5717dd7efd646e0a0e5d3958dace89b4f5faefd5fb590ecccba5889bbe5f831962d7e2633c19d4005265bad1cd35f671a33db067d9c0edd724fec939911630ff9eadff4ab8faea60aba1bd807d9c459c3265b881cdfb1e87bfa7ff39505eff7f562ba381114c341f7e6eac0c6822afe1d8098452104a3f7f47efb675473d47df42f033b582c0629da2a1b9c92f4a2a33acb6fff9e1e3721336b0003a4d7205bd24f5d6b3ea0ef6fe43998ddf54228303a58184932e6b8b6ae1a306131cbbc22f65c0a34267cab6530729471fd65881407ea7bbaa1e09ae13927c769edbf30fbafe937f7a7e4a1179cbe85a2f9cd932956ac2bff5e660e7b4fc1cf0b3e958e8e70f9a91c0580d31917bde466b11ca0e37f3930d850b4a0014bdcaf7f6404c8b40597f8ef5fab9f7e543acb81748e450686e3c9b4b5cd2591d271c773f2ba13c4e1ca8ef53264995b4589e11ad4ae55314cb5e161fc1c14874df76ccd8970a6e1b13eb1aa5795270788f8688e34cf5f17ea4922a4f1908f7cabb99171862b306ae459339d5ecf8c5564dea072ac15d999c9aa3c56288daaa8b73f6b842b0a3428f9b1410540000bee3fc73be5e5111b51cc249b8fc8eea556e74252f9788e88335a1b0454147c0bec066b6c34468c37000d928204e1039a13547204c
#TRUST-RSA-SHA256 5424b1965b2df5f2d9269d35ab1701b8a042d1377bb06a42424db0e940d7b13a84adb24de4382ee8dcfb5e6612e98c5cd79f4da1ad654cbc47cbd1d8dc1778a4fb6297357c5e99c4750d3ac5d56d1d35b9367746d142d01138f9d40182214baa9a81c5634fe233600b77a08fdc75f168b3d015c1babf3752a6b43784e60f90a36ae4dcb2fd8d9bb395eecc50ba90628ee7bfc8669fe80a16e666b11e498ccdfbde3f80e3faf6e1ed45fc35d9e75228c20d950c6b7d39368e00f809655ffe41df8141675e077d2abb86a33718106ea51663e0f7cffaa49f6a1440286130dab3d1111eb5418eda28c1075fb6114b930e172192a247fe1b60bd045cbfc43683f0b63d6bd10522b0c410b72b550fda13ac5ea8afc4f3da36a3be06ba90b85f8097bd34978ecd5dbf0fe9804efc99fdde1d0b8876349eb47369aeb76fcc6192fd3f456fef42c901fd2ec2ab1a4890b84a3287fd24a469c6ef9535ee684e0410438aa58e8b7986cb2989e454936280dd166f1577136e17f6fd4e218a98bef2820d4a7a4edb31f026b0607a978d10bbc170ef0f32617043a9c40c59c21cbc64f38d29f3e45eabc63896f28a4e5c49eb93eb6865b03731a4be4f25f3bf54fe009ee323225d05aa592d2c141178a204290db5687788f259c451c4de25c8a934be5f28777a6be939a6af83872dd276962675c5cd61681b17bfbd0812aadce4269261d9ed12
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(138437);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/27");

  script_cve_id("CVE-2018-0307");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve51704");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve91749");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve91768");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180620-nx-os-cli-injection");
  script_xref(name:"IAVA", value:"2020-A-0397-S");

  script_name(english:"Cisco NX-OS Software CLI Arbitrary Command Injection (cisco-sa-20180620-nx-os-cli-injection)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A command injection vulnerability exists in the CLI of Cisco NX-OS Software due to 
insufficient input validation of command arguments. An authenticated, local attacker 
can exploit this, via a vulnerable CLI command to execute arbitrary commands.

Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180620-nx-os-cli-injection
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?38e5ac5c");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-67770");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-67770");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve51704");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve91749");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve91768");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCve51704, CSCve91749, CSCve91768");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0307");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/14");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Model", "Host/Cisco/NX-OS/Device");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco NX-OS Software');

if ('Nexus' >!< product_info.device)
   audit(AUDIT_HOST_NOT, 'affected');

bid = '';
version_list=make_list('');

if ('Nexus' >!< product_info.device) 
  audit(AUDIT_HOST_NOT, 'affected');

if (product_info.model =~ '^(30[0-9][0-9])')
{
  bid ='CSCve51704';
  version_list = [
    {'min_ver' : '0.0', 'fix_ver' : '7.0(3)I4(8)'},
    {'min_ver' : '7.0(3)I5', 'fix_ver' : '7.0(3)I7(1)'}
  ];
}
else if (product_info.model =~ '^(35[0-9][0-9])')
{
  bid ='CSCve91749';
  version_list = [
    {'min_ver' : '6.0', 'fix_ver' : '6.0(2)A8(6)'},
  ];
}
else if (product_info.model =~ '^((20|55|56|60)[0-9][0-9])')
{
  bid ='CSCve91768';
  version_list = [    
    {'min_ver' : '6.0', 'fix_ver' : '7.1(5)N1(1b)'},
    {'min_ver' : '7.2', 'fix_ver' : '7.3(3)N1(1)'}
  ];
}
else if (product_info.model =~ '^((7[70])[0-9][0-9])')
{
  bid ='CSCve51704';
  version_list = [
    {'min_ver' : '6.2', 'fix_ver' : '6.2(20a)'},
    {'min_ver' : '7.2', 'fix_ver' : '7.3(2)D1(3)'},
    {'min_ver' : '8.0', 'fix_ver' : '8.1(2)'}
  ];
}
else if (product_info.model =~ '^(90[0-9][0-9])')
{
  bid ='CSCve51704';
  version_list = [
    {'min_ver' : '0.0', 'fix_ver' : '7.0(3)I4(8)'},
    {'min_ver' : '7.0(3)I5', 'fix_ver' : '7.0(3)I7(1)'}
  ];
}
else if (product_info.model =~ '^(95[0-9][0-9])')
{
  bid ='CSCve51704';
  version_list = [
    {'min_ver' : '7.0', 'fix_ver' : '7.0(3)F3(3a)'},
  ];
}
    
if (bid == '')
  audit(AUDIT_HOST_NOT, 'affected');
    
reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , bid
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:version_list
);
