#TRUSTED 75c67cec6150771a8dbd0a03c100b0783afea72cdd1a063dc66bffa579355ed9ef2fa849981b0842d73d6771962ea950a3e549543e161fa30d2d087623981b9bbd8392c187ff38d3fff9152f2b43759857c5821eb1f1f571957b98573b1c6679b6e0766021a8b57a462e9e19390ce983f9f7795f89f547182c4bcace3fc0cfd4368faa09c74687103f49edb52462859ac1228a88a630b7d44505a23dc1351a847a3dcfacbcf77c944a1475c2061b471050d22a67494efc9d59ccfa2885dc4178688fb0c5cb33c431dc530aff52c2063576425b95e866202dc006697f25d2b3fed169e56e38fb6a093ea7e8c3bf990cc76a056447c385c0edcca30f362700eccf81eef99b4586619e1d752b6311fa1627ac9bd962208ecf2cf43de644d800b9ea6211de99fa0fd3d642aacc4a75af3d7c41afd117f399a41a16b72574077838b27b9992306646007ffe43d0bf8964c4c79e340ce26c7777f56cbd9e426532806abb5b039bbef6f411841dfb96b218bf34e46c2e0f879eb7ae2bbca5246562ebdb38a03f5a60c10526111f2d0bf082a4cb00b59602597ceed400ae7ccb51f08dba9d0186f875c470a5bb9f8ecd7fc6139d9ceda729c2eb2f1de11d99d28ccc9bb551557883bb509d997c89a291631e4169940a4b63f5b9d4ef65f6531b14c5b561eedde3ac79c0436371ca8a5bdc5427c5a12db73bd3e0de12508f90b45e739024
#TRUST-RSA-SHA256 1d24e4b0743e4f175d42bc8f99eefcd82560ed0b12728513528c1bd0d4d9d7fbbc27955f3283ea7bb98bd1b17befb6181bc9e5e9a09ac3cc8b4e2edaacf4e42a4f1aff7713a4a7f0e2889f229928a4b3672b2a6ba1f7de25d05a7a8dab5cc25c5e23e6780407c279289c6be7e8d896ec3f0de2b126ea7751e763c45fafcf41206e04a810acefe558f1c4ad83e21f692cda7e8fa0d859a76d31c632d91b8b735b5a9ab877dcf867530d659ccb3e97f0c2a19a1071e6811edaae96226bfaf349917053ce5515b7985eddf8fe47a14a6bcc1f0c310f657dc839f613126d244e6fd21b6fdc424c36590487f3f92c78732cfe55a72aa1b7beabe60fae6005265430647e8340137859ba85c52a88b5330ebdec77292a49a289724d6e94d62830259c8d4bae077c80694a0b3c476a7a0338fbee9d5ea971ddad8724a4cc38eef671a07ed40be114914e76e6f2cdb49d7d4faea555d63aeb0893ea4d733491e5fd41bfae1259d2df3a68ac028158849241338c6a26ee72f3f8ebabe71f084011b9e2c301c56b9ae5eea73f96d9e61512e859b9547c9f7a22c5f2d98f6e7816ff97832c92aa291c36f034bfb5cb78cc491e85940d15629ea4397e640d74d5b3c0fb001adb352f2cdbce1a8eb1f091aa0d6724b919258af1109822e8784d54b8b97d3cfa04f748e1523ae798eef15bae321ac98c86bea0e99727b36f4eaeec99e12a26379c
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(191465);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/27");

  script_cve_id("CVE-2024-20321");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwh09703");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwh96478");
  script_xref(name:"CISCO-SA", value:"cisco-sa-nxos-ebgp-dos-L3QCwVJ");
  script_xref(name:"IAVA", value:"2024-A-0119-S");

  script_name(english:"Cisco Nexus 3600 External BGP DoS (cisco-sa-nxos-po-acl-TkyePgvL)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the External Border Gateway Protocol (eBGP) implementation of Cisco NX-OS Software could allow an unauthenticated, remote attacker to cause a denial of service (DoS) condition on an affected device.

This vulnerability exists because eBGP traffic is mapped to a shared hardware rate-limiter queue. An attacker could 
exploit this vulnerability by sending large amounts of network traffic with certain characteristics through an affected
device. A successful exploit could allow the attacker to cause eBGP neighbor sessions to be dropped, leading to a DoS 
condition in the network.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nxos-ebgp-dos-L3QCwVJ
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1e3d5bb2");
  # https://sec.cloudapps.cisco.com/security/center/viewErp.x?alertId=ERP-75059
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e327a04a");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwh09703");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwh96478");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCwh09703, CSCwh96478");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20321");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(400);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/03/01");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Model", "Host/Cisco/NX-OS/Device", "Settings/ParanoidReport");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco NX-OS Software');

# We cannot test for the full vulnerable condition
if (report_paranoia < 2) audit(AUDIT_PARANOID);

# Just Nexus 3600 Series Switches for now
if (('Nexus' >!< product_info.device || product_info.model !~ "(^|[^0-9])36[0-9]{2,3}"))
audit(AUDIT_HOST_NOT, 'affected');

# Bug Checker is showing 10.4(2) as the first fixed or not affected version, see http://www.nessus.org/u?3f81dca0
var version_list = make_list(
  '6.0(2)A3(1)',
  '6.0(2)A3(2)',
  '6.0(2)A3(4)',
  '6.0(2)A4(1)',
  '6.0(2)A4(2)',
  '6.0(2)A4(3)',
  '6.0(2)A4(4)',
  '6.0(2)A4(5)',
  '6.0(2)A4(6)',
  '6.0(2)A6(1)',
  '6.0(2)A6(1a)',
  '6.0(2)A6(2)',
  '6.0(2)A6(2a)',
  '6.0(2)A6(3)',
  '6.0(2)A6(3a)',
  '6.0(2)A6(4)',
  '6.0(2)A6(4a)',
  '6.0(2)A6(5)',
  '6.0(2)A6(5a)',
  '6.0(2)A6(5b)',
  '6.0(2)A6(6)',
  '6.0(2)A6(7)',
  '6.0(2)A6(8)',
  '6.0(2)A7(1)',
  '6.0(2)A7(1a)',
  '6.0(2)A7(2)',
  '6.0(2)A7(2a)',
  '6.0(2)A8(1)',
  '6.0(2)A8(2)',
  '6.0(2)A8(3)',
  '6.0(2)A8(4)',
  '6.0(2)A8(4a)',
  '6.0(2)A8(5)',
  '6.0(2)A8(6)',
  '6.0(2)A8(7)',
  '6.0(2)A8(7a)',
  '6.0(2)A8(7b)',
  '6.0(2)A8(8)',
  '6.0(2)A8(9)',
  '6.0(2)A8(10a)',
  '6.0(2)A8(10)',
  '6.0(2)A8(11)',
  '6.0(2)A8(11a)',
  '6.0(2)A8(11b)',
  '6.0(2)U2(1)',
  '6.0(2)U2(2)',
  '6.0(2)U2(3)',
  '6.0(2)U2(4)',
  '6.0(2)U2(5)',
  '6.0(2)U2(6)',
  '6.0(2)U3(1)',
  '6.0(2)U3(2)',
  '6.0(2)U3(3)',
  '6.0(2)U3(4)',
  '6.0(2)U3(5)',
  '6.0(2)U3(6)',
  '6.0(2)U3(7)',
  '6.0(2)U3(8)',
  '6.0(2)U3(9)',
  '6.0(2)U4(1)',
  '6.0(2)U4(2)',
  '6.0(2)U4(3)',
  '6.0(2)U4(4)',
  '6.0(2)U5(1)',
  '6.0(2)U5(2)',
  '6.0(2)U5(3)',
  '6.0(2)U5(4)',
  '6.0(2)U6(1)',
  '6.0(2)U6(2)',
  '6.0(2)U6(3)',
  '6.0(2)U6(4)',
  '6.0(2)U6(5)',
  '6.0(2)U6(6)',
  '6.0(2)U6(7)',
  '6.0(2)U6(8)',
  '6.0(2)U6(1a)',
  '6.0(2)U6(2a)',
  '6.0(2)U6(3a)',
  '6.0(2)U6(4a)',
  '6.0(2)U6(5a)',
  '6.0(2)U6(5b)',
  '6.0(2)U6(5c)',
  '6.0(2)U6(9)',
  '6.0(2)U6(10)',
  '6.0(2)U6(10a)',
  '7.0(3)F3(1)',
  '7.0(3)F3(2)',
  '7.0(3)F3(3)',
  '7.0(3)F3(3a)',
  '7.0(3)F3(4)',
  '7.0(3)F3(3c)',
  '7.0(3)F3(5)',
  '7.0(3)I2(2a)',
  '7.0(3)I2(2b)',
  '7.0(3)I2(2c)',
  '7.0(3)I2(2d)',
  '7.0(3)I2(2e)',
  '7.0(3)I2(3)',
  '7.0(3)I2(4)',
  '7.0(3)I2(5)',
  '7.0(3)I2(1)',
  '7.0(3)I2(1a)',
  '7.0(3)I2(2)',
  '7.0(3)I2(2r)',
  '7.0(3)I2(2s)',
  '7.0(3)I2(2v)',
  '7.0(3)I2(2w)',
  '7.0(3)I2(2x)',
  '7.0(3)I2(2y)',
  '7.0(3)I3(1)',
  '7.0(3)I4(1)',
  '7.0(3)I4(2)',
  '7.0(3)I4(3)',
  '7.0(3)I4(4)',
  '7.0(3)I4(5)',
  '7.0(3)I4(6)',
  '7.0(3)I4(7)',
  '7.0(3)I4(8)',
  '7.0(3)I4(8a)',
  '7.0(3)I4(8b)',
  '7.0(3)I4(8z)',
  '7.0(3)I4(1t)',
  '7.0(3)I4(6t)',
  '7.0(3)I4(9)',
  '7.0(3)I5(1)',
  '7.0(3)I5(2)',
  '7.0(3)I5(3)',
  '7.0(3)I5(3a)',
  '7.0(3)I5(3b)',
  '7.0(3)I6(1)',
  '7.0(3)I6(2)',
  '7.0(3)I7(1)',
  '7.0(3)I7(2)',
  '7.0(3)I7(3)',
  '7.0(3)I7(4)',
  '7.0(3)I7(5)',
  '7.0(3)I7(5a)',
  '7.0(3)I7(3z)',
  '7.0(3)I7(6)',
  '7.0(3)I7(6z)',
  '7.0(3)I7(7)',
  '7.0(3)I7(8)',
  '7.0(3)I7(9)',
  '7.0(3)I7(9w)',
  '7.0(3)I7(10)',
  '9.2(1)',
  '9.2(2)',
  '9.2(2t)',
  '9.2(3)',
  '9.2(3y)',
  '9.2(4)',
  '9.2(2v)',
  '9.3(1)',
  '9.3(2)',
  '9.3(3)',
  '9.3(4)',
  '9.3(5)',
  '9.3(6)',
  '9.3(7)',
  '9.3(7k)',
  '9.3(7a)',
  '9.3(8)',
  '9.3(9)',
  '9.3(10)',
  '9.3(11)',
  '10.1(1)',
  '10.1(2)',
  '10.1(2t)',
  '10.2(1)',
  '10.2(2)',
  '10.2(3)',
  '10.2(3t)',
  '10.2(4)',
  '10.2(5)',
  '10.3(1)',
  '10.3(2)',
  '10.3(3)',
  '10.4(1)',
  '10.3(4a)'
);

var reporting = make_array(
  'port'    , 0,
  'severity', SECURITY_HOLE,
  'version' , product_info['version'],
  'bug_id'  , 'CSCwh09703, CSCwh96478'
);

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = WORKAROUND_CONFIG['nxos_bgp_neighbor'];

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
