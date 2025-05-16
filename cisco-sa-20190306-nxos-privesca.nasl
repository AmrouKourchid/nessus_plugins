#TRUSTED 8b2e9f44608b20e347e8fe6582cf7a5fb0086e739ef6caadbffea8d22e21f6048c3ef0c5e45f005026a1bf4a8392b1d024539fc624a033fb39c4309ab4028a85e901845f368ebbbc062def95ab0e91c70b8bd1ea6f7594d342ee6f27b5061b01f43fcf9c7a0c20ddf4b37874597d6905ed8973765562e3f0931dc7bfe1781e98d16c9d53e57f1addff2997b6b3abf531447d3462b4eeb4be40060d7bb4c6fe9e4a31d5b8641f50279499c6019a6602faed964d263cb0a3cb518f0dcfed0cf90ff945b5c7b00938c47f4ca6c6e353f6f3626656ab224fc64972c716c7cfe4b79e78d3f41160d241df2341c9a78f6eb6b9bc4f92b0b9efaa74975080a1856150c18a280344627f34735c3b538c541c90a31a40dc49fdf1f2a20e2d0e79063cac099de76cfd5fb9ba5945a748a92479b271bf6dbe8288b78e1907def89c5ea8a763cd532018dcdb3fdc916af0d3028440c912306dafb6b08f788d5570427cbc55eb74748a7d9c6d147bb9cc02f5a57b0b0646d882bac247082805c6ae2cf759775163cfb2435f34b50bd6730a7a2dbd2b480ac5ce569435efeba6e1ec27171e80cd2d38ea232c5bcd9dbd004c2b0398491a25c683f90084009d5e9057460a2c975dc02481615295923f35baca346ea7b58d8db6c73aa33b97da7f58d7e90f585d4517e90364ebb2bed368357f223f42978bcd27fbe7b9ab4f05a065a5cacbe0115a
#TRUST-RSA-SHA256 9c62ee5193ba3a084f9ef11023c61f844f6fdecb6268db3a6deb78e5e4e7e4464027f73feeb4a1ea7ecb9df5b932c514b35b590ef2947871950ff211f9090815dc4723547d39743d0acd09202d9dabb52cfa8855e36dfeeeb13ff60ec30c0f4ddabd0e2363e0aaa0ba6f15f56be364e31f50e76ca16aa44d3471fbfe64b58d8c1115607969fbfbde516689f1d46cbbf78eef902a36dd19f19b90c61ff7ec50dc83e1042f8b4894f63798b090097c6f7be9304b2e7f90a9a9e2354d6ae5d309ed03437644dffa8d6a70f6ba81e81733e4131ec9d1f9923b683b664afd8ec328ee157f3ef97e2348bd2bec940b7e32536ab9244718d972f3b908b7f55b7e2106fb16433ac6ae37f04458e27223c3fe7d2cf9cc768d400856be07b321bdccd0eb69ab989f6f1066fda68956a10a0dd57936251b50380b2b31326e3bc445e2b853eb674d4c5a8b6bc0dd629dba011ee9beb0bfb7e5ff55f12e31507dfbf5f292ac634534fb6a1b8861d8e07c6bfbd2fdb64b6bfe092ad7f3d2195a44b3a2c583309633a8dbeab7e69cc9d119372ff8fe904b9cac78eba7e964148a999f6922404bad21422c190fc3f20d00cfa3126cc586081f03fe8035ba01cea07a5fb3248466df409e2700a120ef7f2c65da655fea45d293588a067df81d1ab668238663dfafc7bc7dcdc2b282f546cb8b37c12e875b4d98bfd938d07560021f3960b886809fed
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(132100);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/03");

  script_cve_id("CVE-2019-1604");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi53896");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190306-nxos-privesca");

  script_name(english:"Cisco NX-OS Software Privilege Escalation Vulnerability");
  script_summary(english:"Checks the version of Cisco NX-OS Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco NX-OS Software is
affected by following vulnerability

  - A vulnerability in the user account management interface
    of Cisco NX-OS Software could allow an authenticated,
    local attacker to gain elevated privileges on an
    affected device.The vulnerability is due to an incorrect
    authorization check of user accounts and their
    associated Group ID (GID). An attacker could exploit
    this vulnerability by taking advantage of a logic error
    that will permit the use of higher privileged commands
    than what is necessarily assigned. A successful exploit
    could allow an attacker to execute commands with
    elevated privileges on the underlying Linux shell of an
    affected device. (CVE-2019-1604)

Please see the included Cisco BIDs and Cisco Security Advisory for
more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190306-nxos-privesca
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2494752e");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-70757");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi53896");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvi53896");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1604");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(285);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/18");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Model", "Host/Cisco/NX-OS/Device", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("cisco_workarounds.inc");
include("ccf.inc");

product_info = cisco::get_product_info(name:"Cisco NX-OS Software");

switch (product_info)
{
  case product_info.model =~ "30[0-9][0-9]":
    version_list=make_list(
      "7.0(3)I7(4)",
      "7.0(3)I7(3)",
      "7.0(3)I7(2)",
      "7.0(3)I7(1)",
      "7.0(3)I6(2)",
      "7.0(3)I6(1)",
      "7.0(3)I5(2)",
      "7.0(3)I5(1)",
      "7.0(3)I4(8z)",
      "7.0(3)I4(8b)",
      "7.0(3)I4(8a)",
      "7.0(3)I4(8)",
      "7.0(3)I4(7)",
      "7.0(3)I4(6)",
      "7.0(3)I4(5)",
      "7.0(3)I4(4)",
      "7.0(3)I4(3)",
      "7.0(3)I4(2)",
      "7.0(3)I4(1)",
      "7.0(3)I3(1)",
      "7.0(3)I2(5)",
      "7.0(3)I2(4)",
      "7.0(3)I2(3)",
      "7.0(3)I2(2e)",
      "7.0(3)I2(2d)",
      "7.0(3)I2(2c)",
      "7.0(3)I2(2b)",
      "7.0(3)I2(2a)",
      "7.0(3)I2(2)",
      "7.0(3)I2(1a)",
      "7.0(3)I2(1)",
      "7.0(3)I1(3b)",
      "7.0(3)I1(3a)",
      "7.0(3)I1(3)",
      "7.0(3)I1(2)",
      "7.0(3)I1(1b)",
      "7.0(3)I1(1a)",
      "7.0(3)I1(1)",
      "7.0(3)F3(4)",
      "7.0(3)F3(3c)",
      "7.0(3)F3(3b)",
      "7.0(3)F3(3a)",
      "7.0(3)F3(3)",
      "7.0(3)F3(2)",
      "7.0(3)F3(1)",
      "7.0(3)F2(2)",
      "7.0(3)F2(1)",
      "7.0(3)F1(1)",
      "7.0(2)I2(2c)"
	);
	bugID = "CSCvi53896";
  break;
  case product_info.model =~ "35[0-9][0-9]": #3500 series
    version_list=make_list(
      "7.0(3)I7(4)",
      "7.0(3)I7(3)",
      "7.0(3)I7(2)",
      "7.0(3)I7(1)",
      "7.0(3)I6(2)",
      "7.0(3)I6(1)",
      "7.0(3)I5(2)",
      "7.0(3)I5(1)",
      "7.0(3)I4(8z)",
      "7.0(3)I4(8b)",
      "7.0(3)I4(8a)",
      "7.0(3)I4(8)",
      "7.0(3)I4(7)",
      "7.0(3)I4(6)",
      "7.0(3)I4(5)",
      "7.0(3)I4(4)",
      "7.0(3)I4(3)",
      "7.0(3)I4(2)",
      "7.0(3)I4(1)",
      "7.0(3)I3(1)",
      "7.0(3)I2(5)",
      "7.0(3)I2(4)",
      "7.0(3)I2(3)",
      "7.0(3)I2(2e)",
      "7.0(3)I2(2d)",
      "7.0(3)I2(2c)",
      "7.0(3)I2(2b)",
      "7.0(3)I2(2a)",
      "7.0(3)I2(2)",
      "7.0(3)I2(1a)",
      "7.0(3)I2(1)",
      "7.0(3)I1(3b)",
      "7.0(3)I1(3a)",
      "7.0(3)I1(3)",
      "7.0(3)I1(2)",
      "7.0(3)I1(1b)",
      "7.0(3)I1(1a)",
      "7.0(3)I1(1)",
      "7.0(3)F3(4)",
      "7.0(3)F3(3c)",
      "7.0(3)F3(3b)",
      "7.0(3)F3(3a)",
      "7.0(3)F3(3)",
      "7.0(3)F3(2)",
      "7.0(3)F3(1)",
      "7.0(3)F2(2)",
      "7.0(3)F2(1)",
      "7.0(3)F1(1)",
      "7.0(2)I2(2c)",
      "6.0(2)A8(9)",
      "6.0(2)A8(8)",
      "6.0(2)A8(7b)",
      "6.0(2)A8(7a)",
      "6.0(2)A8(7)",
      "6.0(2)A8(6)",
      "6.0(2)A8(5)",
      "6.0(2)A8(4a)",
      "6.0(2)A8(4)",
      "6.0(2)A8(3)",
      "6.0(2)A8(2)",
      "6.0(2)A8(10a)",
      "6.0(2)A8(10)",
      "6.0(2)A8(1)",
      "6.0(2)A7(2a)",
      "6.0(2)A7(2)",
      "6.0(2)A7(1a)",
      "6.0(2)A7(1)",
      "6.0(2)A6(8)",
      "6.0(2)A6(7)",
      "6.0(2)A6(6)",
      "6.0(2)A6(5b)",
      "6.0(2)A6(5a)",
      "6.0(2)A6(5)",
      "6.0(2)A6(4a)",
      "6.0(2)A6(4)",
      "6.0(2)A6(3a)",
      "6.0(2)A6(3)",
      "6.0(2)A6(2a)",
      "6.0(2)A6(2)",
      "6.0(2)A6(1a)",
      "6.0(2)A6(1)",
      "6.0(2)A4(6)",
      "6.0(2)A4(5)",
      "6.0(2)A4(4)",
      "6.0(2)A4(3)",
      "6.0(2)A4(2)",
      "6.0(2)A4(1)",
      "6.0(2)A3(4)",
      "6.0(2)A3(2)",
      "6.0(2)A3(1)",
      "6.0(2)A1(2d)",
      "6.0(2)A1(1f)",
      "6.0(2)A1(1e)",
      "6.0(2)A1(1d)",
      "6.0(2)A1(1c)",
      "6.0(2)A1(1b)",
      "6.0(2)A1(1a)",
      "6.0(2)A1(1)",
      "6.0(2)",
      "6.0(1)",
      "5.2(9a)",
      "5.2(9)N1(1)",
      "5.2(9)",
      "5.2(7)",
      "5.2(5)",
      "5.2(4)",
      "5.2(3a)",
      "5.2(3)",
      "5.2(1)",
      "5.1(6)",
      "5.1(5)",
      "5.1(4)",
      "5.1(3)",
      "5.1(1a)",
      "5.1(1)",
      "5.0(5)",
      "5.0(3)U5(1j)",
      "5.0(3)U5(1i)",
      "5.0(3)U5(1h)",
      "5.0(3)U5(1g)",
      "5.0(3)U5(1f)",
      "5.0(3)U5(1e)",
      "5.0(3)U5(1d)",
      "5.0(3)U5(1c)",
      "5.0(3)U5(1b)",
      "5.0(3)U5(1a)",
      "5.0(3)U5(1)",
      "5.0(3)U4(1)",
      "5.0(3)U3(2b)",
      "5.0(3)U3(2a)",
      "5.0(3)U3(2)",
      "5.0(3)U3(1)",
      "5.0(3)U2(2d)",
      "5.0(3)U2(2c)",
      "5.0(3)U2(2b)",
      "5.0(3)U2(2a)",
      "5.0(3)U2(2)",
      "5.0(3)U2(1)",
      "5.0(3)U1(2a)",
      "5.0(3)U1(2)",
      "5.0(3)U1(1d)",
      "5.0(3)U1(1c)",
      "5.0(3)U1(1b)",
      "5.0(3)U1(1a)",
      "5.0(3)U1(1)",
      "5.0(3)A1(2a)",
      "5.0(3)A1(2)",
      "5.0(3)A1(1)",
      "5.0(3)",
      "5.0(2a)",
      "4.2(8)",
      "4.2(6)",
      "4.2(4)",
      "4.2(3)",
      "4.2(2a)",
      "4.1(5)",
      "4.1(4)",
      "4.1(3)",
      "4.1(2)"
);
	bugID = "CSCvk70990";
  break;
  case product_info.model =~ "36[0-9][0-9]": #3600 series
    version_list=make_list(
      "7.0(3)F3(4)",
      "7.0(3)F3(3c)",
      "7.0(3)F3(3b)",
      "7.0(3)F3(3a)",
      "7.0(3)F3(3)",
      "7.0(3)F3(2)",
      "7.0(3)F3(1)",
      "7.0(3)F2(2)",
      "7.0(3)F2(1)",
      "7.0(3)F1(1)"
	);
	bugID = "CSCvm35213";
  break;
  case product_info.model =~ "(70|77)[0-9][0-9]": #7000 and 7700 series
    if (report_paranoia < 2) audit(AUDIT_PARANOID);
    vuln_list = [
      {'min_ver' : '0', 'fix_ver' : '6.2(22)'},
      {'min_ver' : '8.1', 'fix_ver' : '8.3(2)'}
    ];
	bugID = "CSCvm35215";
  break;
  case product_info.model =~ "90[0-9][0-9]": #9000 series
    version_list=make_list(
      "7.0(3)I7(4)",
      "7.0(3)I7(3)",
      "7.0(3)I7(2)",
      "7.0(3)I7(1)",
      "7.0(3)I6(2)",
      "7.0(3)I6(1)",
      "7.0(3)I5(2)",
      "7.0(3)I5(1)",
      "7.0(3)I4(8z)",
      "7.0(3)I4(8b)",
      "7.0(3)I4(8a)",
      "7.0(3)I4(8)",
      "7.0(3)I4(7)",
      "7.0(3)I4(6)",
      "7.0(3)I4(5)",
      "7.0(3)I4(4)",
      "7.0(3)I4(3)",
      "7.0(3)I4(2)",
      "7.0(3)I4(1)",
      "7.0(3)I3(1)",
      "7.0(3)I2(5)",
      "7.0(3)I2(4)",
      "7.0(3)I2(3)",
      "7.0(3)I2(2e)",
      "7.0(3)I2(2d)",
      "7.0(3)I2(2c)",
      "7.0(3)I2(2b)",
      "7.0(3)I2(2a)",
      "7.0(3)I2(2)",
      "7.0(3)I2(1a)",
      "7.0(3)I2(1)",
      "7.0(3)I1(3b)",
      "7.0(3)I1(3a)",
      "7.0(3)I1(3)",
      "7.0(3)I1(2)",
      "7.0(3)I1(1b)",
      "7.0(3)I1(1a)",
      "7.0(3)I1(1)",
      "7.0(3)F3(4)",
      "7.0(3)F3(3c)",
      "7.0(3)F3(3b)",
      "7.0(3)F3(3a)",
      "7.0(3)F3(3)",
      "7.0(3)F3(2)",
      "7.0(3)F3(1)",
      "7.0(3)F2(2)",
      "7.0(3)F2(1)",
      "7.0(3)F1(1)",
      "7.0(2)I2(2c)"
	);
	bugID = "CSCvi53896";
  break;
  case product_info.model =~ "95[0-9][0-9]": #9500 series
    version_list=make_list(
      "7.0(3)F3(4)",
      "7.0(3)F3(3c)",
      "7.0(3)F3(3b)",
      "7.0(3)F3(3a)",
      "7.0(3)F3(3)",
      "7.0(3)F3(2)",
      "7.0(3)F3(1)",
      "7.0(3)F2(2)",
      "7.0(3)F2(1)",
      "7.0(3)F1(1)"
	);
	bugID = "CSCvm35213";
  break;
  case product_info.device != 'Nexus': #This is purposeful. Case fall through for failure specific conditions.
  default:
    audit(AUDIT_HOST_NOT, 'affected');
}
reporting = make_array(
'port'     , 0,
'disable_caveat' , 1,
'severity' , SECURITY_HOLE,
'version'  , product_info['version'],
'bug_id'   , bugID
);

cisco::check_and_report(product_info:product_info, reporting:reporting, vuln_versions:version_list, vuln_ranges:vuln_list);
