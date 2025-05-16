#TRUSTED 3e4189e78973c85eec66cf8f7ea7969258dbbf6e559cfcb881ac286c9d8bd2a5a2d74c2e9863d78c50b20dff32fe8cac691dc1aa55726f86bbbacf24af9377a6493fc13033e85b28c610153df5968400ede071d8ea5f4b51dbf74a87ef564aea72581b91135901ba6bd65c54e3197af69f7ed6a800d06c00546cff0690a1375541dd477ffe51f439ba75a49b4f4e0f9e60b46b62d54caa0af50e799a5c3f3c60dc0fa2b5331feebaf82e2303b2c538144a7f58d8b0102a4730f0bb1a6dee97c157c8574cf37164410c964ba8a62106cd750dc7f89bccc2ae0a91d93689edc8de4d310989efdc576ee832bfb1a614f517fd41db4cce41cd6ca12475dfa190db577924d455908d1c324e6db800a44231b6b7652925d21e6937340d3cc58affe8443a08b151e474f2eb7b6a2228d54d879868361371b6fdbcae2b2ebae69a4f8a8a9e8e7e8a473e9149def0aca6ffdb92fca9669b00cbd53818b3cfaa28c8df2a710331fa0f1b08a8890f584ef1e491a2da0d24f66f910093ef022de3733ba63db8794adbff39f6c8569bb1fc581479221534ceebfb80de7d53e923c44d6323c0fac1d44652d2866b4f169f9d274065fd4cf567e675fb3c4a23ab34e8db136d97a82ae461e44ef33cd79b5c74e03d6dde4cca237f845a63fbf2a410a12ff79f623536cc0b711d60403215e63713880bf70a45e6478d47c6f663b63d6d1226f6823d
#TRUST-RSA-SHA256 616970b827cc3c9db2cf62e9ce3748ac91176d60f403b4eb6c66051acc130d0ef61ad09c382618170d491b7a319e6c9c2d9ae579b9d6c2edb09d53d7594d663a3a3f2db74da1229c3ecc320503401582d57914df989fbd3b72d8b4904ae07eddac9be1bce1f4539d38c807d6760e74b398dca0b639f7e4de0859efc1e5957aedb320715155f80d6aac64330987b592c1e9d6e81bcb87779b8dc22ddb560bb7988bd67789ded561160bda1d18654f7d1b77547cc6d2a5c7ff2a9afa05148ebb24302b3951245102a1d3ce133851b1971eca6fe77d6b9f8ea23bcfd11ccd796529494519318dad67224c61ab4e2f1cef3dba6ca68b72aa79fcbe241e4c548b92373603cb60e8609860dcd07618b2e2a0e4334db240b6f759e3bc29bbe85e79969e8bc775f898686e69ddabf73c53fd2d86682b5cfcfe78dcaa5b1678d5594a54a6847d01cb8343c621ae7a57e955c1c63c9c25bbf6b659eb6bc37bb150a0e4a6e8642403fd1b27f4746022570f28fa5d7354b833d50304f544823ec196f7799158711638516fbb3e386ef2fc7edfcc331d4ac171b093a1d064a6a71f161642db5dc4756217839a98ebc0ae591a57662d248b20dbdc9f0a32b6db0114d3b380b41b42aaf033e504e3af732e5d6d3980da27f118eced699007dee4350e7ee6b0987b2365ec047e5a779f74bf604e33560bc89e752a8caa67b4a72a59a33a8416dbbb
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(191469);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/27");

  script_cve_id("CVE-2024-20267");
  script_xref(name:"CISCO-BUG-ID", value:"CSCva52387");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwh42690");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ipv6-mpls-dos-R9ycXkwM");
  script_xref(name:"IAVA", value:"2024-A-0119-S");

  script_name(english:"Cisco NX-OS Software MPLS Encapsulated IPv6 DoS (cisco-sa-ipv6-mpls-dos-R9ycXkwM)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A vulnerability with the handling of MPLS traffic for Cisco NX-OS Software could allow an unauthenticated, remote 
attacker to cause the netstack process to unexpectedly restart, which could cause the device to stop processing network 
traffic or to reload. This vulnerability is due to lack of proper error checking when processing an ingress MPLS frame. 
An attacker could exploit this vulnerability by sending a crafted IPv6 packet that is encapsulated within an MPLS frame 
to an MPLS-enabled interface of the targeted device. A successful exploit could allow the attacker to cause a denial of 
service (DoS) condition. Note: The IPv6 packet can be generated multiple hops away from the targeted device and then 
encapsulated within MPLS. The DoS condition may occur when the NX-OS device processes the packet.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ipv6-mpls-dos-R9ycXkwM
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f3c8adc2");
  # https://sec.cloudapps.cisco.com/security/center/viewErp.x?alertId=ERP-75059
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e327a04a");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCva52387");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwh42690");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCva52387, CSCwh42690");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20267");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(120);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/03/01");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Model", "Host/Cisco/NX-OS/Device");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco NX-OS Software');

if ('Nexus' >!< product_info.device || product_info.model !~ "([3679][0-9]{2,3})|(5[56][0-9]{1,2})")
  audit(AUDIT_HOST_NOT, 'affected');

var version_list = [];

if ('Nexus' >< product_info.device && product_info.model =~ "^3[0-9]{2,3}")
{
  version_list = make_list(
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
    '10.3(1)',
    '10.3(2)',
    '10.3(3)',
    '10.4(1)'
  );
}

if ('Nexus' >< product_info.device && product_info.model =~ "^7[0-9]{2,3}")
{
  version_list = make_list(
    '6.2(2)',
    '6.2(2a)',
    '6.2(6)',
    '6.2(6b)',
    '6.2(8)',
    '6.2(8a)',
    '6.2(8b)',
    '6.2(10)',
    '6.2(12)',
    '6.2(18)',
    '6.2(16)',
    '6.2(14b)',
    '6.2(14)',
    '6.2(14a)',
    '6.2(6a)',
    '6.2(20)',
    '6.2(20a)',
    '6.2(22)',
    '6.2(24)',
    '6.2(24a)',
    '6.2(26)',
    '7.2(0)D1(1)',
    '7.2(1)D1(1)',
    '7.2(2)D1(2)',
    '7.2(2)D1(1)',
    '7.2(2)D1(3)',
    '7.2(2)D1(4)',
    '7.3(0)D1(1)',
    '7.3(0)DX(1)'
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
    '10.1(1)',
    '10.1(2)',
    '10.2(1)',
    '10.2(1q)',
    '10.2(2)',
    '10.2(3)',
    '10.2(2a)',
    '10.2(3t)',
    '10.2(4)',
    '10.2(5)',
    '10.2(6)',
    '10.3(1)',
    '10.3(2)',
    '10.3(3)',
    '10.3(99w)',
    '10.3(3w)',
    '10.3(99x)',
    '10.3(3o)',
    '10.3(3p)',
    '10.3(3q)',
    '10.4(1)'
  );
}

if ('Nexus' >< product_info.device && product_info.model =~ "^5[56][0-9]{1,2}|^6[0-9]{2,3}")
{
  version_list = make_list(
    '7.1(0)N1(1a)',
    '7.1(0)N1(1b)',
    '7.1(0)N1(1)',
    '7.1(1)N1(1)',
    '7.1(1)N1(1a)',
    '7.1(2)N1(1)',
    '7.1(2)N1(1a)',
    '7.1(3)N1(1)',
    '7.1(3)N1(2)',
    '7.1(3)N1(5)',
    '7.1(3)N1(4)',
    '7.1(3)N1(3)',
    '7.1(3)N1(2a)',
    '7.1(4)N1(1)',
    '7.1(4)N1(1d)',
    '7.1(4)N1(1c)',
    '7.1(4)N1(1a)',
    '7.1(5)N1(1)',
    '7.1(5)N1(1b)',
    '7.3(0)N1(1)',
    '7.3(0)N1(1b)',
    '7.3(0)N1(1a)'
  );
}

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = [WORKAROUND_CONFIG['show_mpls_interfaces_detail']];

var reporting = make_array(
  'port'    , 0,
  'severity', SECURITY_HOLE,
  'version' , product_info['version'],
  'bug_id'  , 'CSCva52387, CSCwh42690',
  'cmds'    , make_list('show mpls interface detail') 
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);