#TRUSTED 4763258b156380b705ad5cfdbd9c72baeea7dcc426beea4e643a5392e4a53b2fc38d945e416a9ed2d668bbd12826eca531f859c44000e3b1cd23924dc65b56cd34f3585499db6d9db6abcc12f5a8c2030f06012acf31755d9e37e5d51ab3682f54514b1b5ab2c83c5a22d945afdd3dc251c492634c15fa4a2facaec1e879c9fe736c15ea1c880719b93cf029faa081d0ecedce7737e9fbb017a6b488f5cb275c9402b737ae9f3ad3fbc8d2812246706cde39924c24d1da56cd889c1667bafad69befaa4636a7b2a3670b8b7ec9b8fd9b221232fca5e2c5edbf8baee9eca9dbddf42cfcb8a6037d9abae708b0395e8e3b9778ce988f1eb90e36000c8752727974b372b2cede7d4dbd00a738b40bddd0660c6632aa25e9ce0edcc33beb3abea7194b6b23c2aaa0c6c306862af753485999aa8e34a1fa442b02b01985cd36bf97f1c7548f6659cab113f5062501ba57a1cfe193db80d81309a17c5e0fe002ee64dab57e7b64c2f7b1f57994a1ec8a2804ccb1fb8382c839fa0a423b2f3adc6f39f6c65820a4bda649ae890dcaabb934f18cd7f5db8a4b80a7cbc9ed730df10b96a8cd0d68a6559f9bea185f970ff83ac76f01d9a39e481203818c4091ff5b4348c3266914e59345166f850c675b3360f1971827e6c03ee5c38bd1f38c86e36b959da9ecb312c045be2df60122e138ed8d14393898c85a87b00755f4d3082e15d528
#TRUST-RSA-SHA256 85e9e697be405e2cfae5de9ef360d89f455d6d5922fae387b03addc7f4cf02ef90d13773b6ea011f160246be10d9afd775a472fe9451c4f71a61801cdbbe330b17e50108eee119e1bcbf4a239948e96c5a4c9641fdb8ce4f31901010e3dbf4e4f2a85709435c7eec93858f2083bf8caf24cc5c059b8d87082ec7284679e1f4678163c328c40b4a0893708d5bd68285e2f0ccc93dc8429cdbfb0fed652c2614b390adeef76719c71f19cd456e4eb24d5d8655a668864f5315cfc998e1377b5ab13e4211d2d5a539ce25c55df023ef4fd02b7779041c3c2f280e28d3d072b3fc6c1beaab7ad2ef1cf5b1147f14568136f06a915eb4c305a8a2c1b88dcb1bb91ffe5abfe3ec3c39d5d48fe091b3f1a6aa9b56eee4c7fc561893c9e926432a03d4050323b66c64c9e0bc159439345693c93dcbb04e6da6d2cb7d1e322cf8f88fdce53fecc8bb9dd2202f41d29ff460cc203116553fff0f1910226a3e44f6b0785fde6c29a4f72a3cbcbbd79f38db1e5dc152d2c494ea3e4ea0f3c2e75b0bbad967fccefc515a3a534156e3192e773391f890027f229f3939419c2bb208b66648563fed67e171d1e67149886c07017679a6173727bd4446c51728d2da30cc4a531d9340552b53b830bc09c0fdf7ba7aa657edfb32b46f1537f3acf4efbc5033e49e6af9cb743bff7d9ef39fb8a727d70c742398d06af94a27360c9ea5144d8be67020
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(206351);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/27");

  script_cve_id("CVE-2024-20411", "CVE-2024-20413");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwh77783");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwh77791");
  script_xref(name:"CISCO-SA", value:"cisco-sa-nxos-bshacepe-bApeHSx7");
  script_xref(name:"IAVA", value:"2024-A-0529-S");

  script_name(english:"Cisco NX-OS Software Bash Arbitrary Code Execution Privilege Escalation Multiple Vulnerabilities (cisco-sa-nxos-bshacepe-bApeHSx7)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco NX-OS Software is affected by multiple vulnerabilities.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nxos-bshacepe-bApeHSx7
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0b6c6d88");
  # https://sec.cloudapps.cisco.com/security/center/viewErp.x?alertId=ERP-75417
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0fd3f483");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwh77783");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwh77791");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCwh77783, CSCwh77791");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20411");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-20413");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(267, 862);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/08/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/30");

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

# Due to how the Bash Shell can be set up either globally or individually, 
# we are opting for paranoid detection over direct config checks.

if (report_paranoia < 2) audit(AUDIT_PARANOID);

var product_info = cisco::get_product_info(name:'Cisco NX-OS Software');

if (('Nexus' >!< product_info.device || product_info.model !~ "(^|[^0-9])3[0-9]{2,3}") &&
    ('Nexus' >!< product_info.device || product_info.model !~ "(^|[^0-9])9[0-9]{2,3}"))
audit(AUDIT_HOST_NOT, 'affected');

var version_list = [];

if ('Nexus' >< product_info.device && product_info.model =~ "^3[0-9]{2,3}")
{
  version_list = make_list(
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
    '7.0(3)IC4(4)',
    '7.0(3)IM7(2)',
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
    '9.3(12)',
    '9.3(13)',
    '10.1(1)',
    '10.1(2)',
    '10.1(2t)',
    '10.2(1)',
    '10.2(2)',
    '10.2(3)',
    '10.2(3t)',
    '10.2(4)',
    '10.2(5)',
    '10.2(3v)',
    '10.2(6)',
    '10.2(7)',
    '10.3(1)',
    '10.3(2)',
    '10.3(3)',
    '10.3(4a)',
    '10.3(4)',
    '10.3(5)',
    '10.4(1)',
    '10.4(2)',
    '10.4(3)'
  );
}

if ('Nexus' >< product_info.device && product_info.model =~ "^9[0-9]{2,3}")
{
  version_list = make_list(
    '7.0(3)F1(1)',
    '7.0(3)F2(1)',
    '7.0(3)F2(2)',
    '7.0(3)F3(1)',
    '7.0(3)F3(3)',
    '7.0(3)F3(3a)',
    '7.0(3)F3(4)',
    '7.0(3)F3(3c)',
    '7.0(3)F3(5)',
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
    '7.0(3)I7(7)',
    '7.0(3)I7(8)',
    '7.0(3)I7(9)',
    '7.0(3)I7(9w)',
    '7.0(3)I7(10)',
    '9.2(1)',
    '9.2(2)',
    '9.2(3)',
    '9.2(3y)',
    '9.2(4)',
    '7.0(3)IA7(1)',
    '7.0(3)IA7(2)',
    '7.0(3)IC4(4)',
    '7.0(3)IM3(1)',
    '7.0(3)IM3(2)',
    '7.0(3)IM3(2a)',
    '7.0(3)IM3(2b)',
    '7.0(3)IM3(3)',
    '9.3(1)',
    '9.3(2)',
    '9.3(3)',
    '9.3(1z)',
    '9.3(4)',
    '9.3(5)',
    '9.3(6)',
    '9.3(5w)',
    '9.3(7)',
    '9.3(7k)',
    '9.3(7a)',
    '9.3(8)',
    '9.3(9)',
    '9.3(10)',
    '9.3(11)',
    '9.3(12)',
    '9.3(13)',
    '10.1(1)',
    '10.1(2)',
    '10.2(1)',
    '10.2(1q)',
    '10.2(2)',
    '10.2(3)',
    '10.2(2a)',
    '10.2(4)',
    '10.2(5)',
    '10.2(6)',
    '10.2(7)',
    '10.3(1)',
    '10.3(2)',
    '10.3(3)',
    '10.3(99w)',
    '10.3(3w)',
    '10.3(99x)',
    '10.3(3o)',
    '10.3(4a)',
    '10.3(3p)',
    '10.3(4)',
    '10.3(3q)',
    '10.3(3x)',
    '10.3(5)',
    '10.3(4g)',
    '10.3(3r)',
    '10.4(1)',
    '10.4(2)',
    '10.4(3)'
  );
}

var reporting = make_array(
  'port'    , 0,
  'severity', SECURITY_WARNING,
  'version' , product_info['version'],
  'bug_id'  , 'CSCwh77783, CSCwh77791'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
