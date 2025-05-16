#TRUSTED 19c3650fdc3bb40b598dd3c66defb85cc186ec540023371f2ad4542ccfe4f3d342aa91afbebad0575b692f5ce63e7a7e772cf7628537f5c04fd1a11f51f8aef8b9ce8fbbdc7ce8cc9acd5ace0b7f724ec7ceebf65b677f97ea931ac4eb60d084131cbae317e8432c8c8a1a62dfc6c4de570d5098708f0fd5a57a51fbea8427d91c3ed4b97c62b994904d718ad708d21c9acc5283e3e291de202c3c229b79d06f00ad0d243b3c3a8cbe66823f192ac376acd096fa115fd9427dfed33b34ea4b5c9fd27012fe2ff292b1130801650efe0c3d6b5d7c531a932c94a9bdf768dc3ae6094b19f82412280a77499b85c70bd25aeb7dc37f761ac916babcff5689f533d65f68553b5030b02620f2fac51cf4b37049864a9ab32c100b57e2c34b7c01a781396e0425b5fdf13d40d231172036a3661ab26d40eba4054884bba0eab35eec3417de413afb53e0e196f414f5ba7a0e8ea90d974305e002c7c07cce0945ff713e3d7995fe0fb7ee4bf0cf7f8427c8f2814e3393a34646c536702013515e2c99d5f915540c3cb274a6f487b9930a275c028515060f5a678bacc43dd3e2659a36a696b6355aa08312f1a03e052294b720d5cd6e54b6631b3662139612bf3676f7019984600a98e9ebf64de3e38af8a283df1cdd8fe465354579abe384f29afb5aea49bc139964bd623db89575c8fe561bea00eefada8f71ab554b37c2d358149c2f
#TRUST-RSA-SHA256 3f136dba52d4e8609c9d1be034a15cad0cc173921d3c447f1edbd9e8387e021500dfdd45007b8428a8bea71ec596c59af0a09d6cabf194d998df85928af02f1a068c29fa4a1332f7ca17bb02383037985b09a18d32986ea6d60465974170b8efef7e7a642a81e99e421668f4cd766b165bdc3bf1d87adcf91619de24a805901b9fe08c9aebcf1a67767c8328e9e631be47ebc7b609cb486f1c17fef74a898b2f3aa779544c1caee03db9af0593b47746b7369546e6decfaa81bbf0cd1478939a294047f6816e7cb188bb0c805075ffbb7cf98253cd940ee1ee502f5650ba95a58a562271e05de4fd8950062ba60b23707694a1f0c86da91a7489ff5e686eeb6d3920700b2ea96b9e75b008d6cd6d15ddaf5a897276dba5f7ebbcf0f26adbfc914f8df5d93fa7f171ce15d960cd6b7d9970efd244647452427012ae99bfd5e83b27b1634969a1850c2ef8f4fd7ce33630a92ca6c081c6598228c43647b67adc300497595d48c9c392bb5afee1cebfc8c6c3c2ce6a3f337c699d13d14fc6fb488bc449b34b9818f5c2f4ee1e7e8eefd4e607e88fcd295037c93537a9db8183a2a15568c492102c9985c1865e52a6c3fe03524a8e5fa4133fcb406e04fd432db0e5665f494ea1e810ebf19f2ef82ac58ad87cbe93f7e57f645486f90c86763b46232ad1549de86b8ce34d96d1bf7625ec32022678b425272670c788da98c0166f5e
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(139922);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/08");

  script_cve_id("CVE-2020-3338");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr91853");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr97684");
  script_xref(name:"CISCO-SA", value:"cisco-sa-nxos-pim-memleak-dos-tC8eP7uw");
  script_xref(name:"IAVA", value:"2020-A-0394-S");

  script_name(english:"Cisco NX-OS Software IPv6 Protocol Independent Multicast DoS (cisco-sa-nxos-pim-memleak-dos-tC8eP7uw)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco NX-OS Software is affected by a denial of service (DoS) vulnerability due
to improper error handling when processing inbound PIM6 packets. An unauthenticated, remote attacker can exploit this,
by sending multiple crafted PIM6 packets to an affected device, in order to cause the PIM6 application to leak system
memory and stop processing legitimate PIM6 traffic, leading to a DoS condition on the affected device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nxos-pim-memleak-dos-tC8eP7uw
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?319c006d");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74239");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr91853");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr97684");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvr91853, CSCvr97684");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3338");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(404);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/28");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Model", "Host/Cisco/NX-OS/Device");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco NX-OS Software');

if ('Nexus' >!< product_info.device || product_info.model !~ "^[379][0-9]{3}")
  audit(AUDIT_HOST_NOT, 'an affected model');

#  not 9k in ACI mode
if (!(empty_or_null(get_kb_list('Host/aci/*'))))
    audit(AUDIT_HOST_NOT, 'an affected model due to ACI mode');

if (product_info.model =~ "^[39][0-9]{3}")
  cbi = 'CSCvr91853';
else
  cbi = 'CSCvr97684';

version_list=make_list(
  '5.0(3)A1(1)',
  '5.0(3)A1(2)',
  '5.0(3)A1(2a)',
  '5.0(3)U1(1)',
  '5.0(3)U1(1a)',
  '5.0(3)U1(1b)',
  '5.0(3)U1(1c)',
  '5.0(3)U1(1d)',
  '5.0(3)U1(2)',
  '5.0(3)U1(2a)',
  '5.0(3)U2(1)',
  '5.0(3)U2(2)',
  '5.0(3)U2(2a)',
  '5.0(3)U2(2b)',
  '5.0(3)U2(2c)',
  '5.0(3)U2(2d)',
  '5.0(3)U3(1)',
  '5.0(3)U3(2)',
  '5.0(3)U3(2a)',
  '5.0(3)U3(2b)',
  '5.0(3)U4(1)',
  '5.0(3)U5(1)',
  '5.0(3)U5(1a)',
  '5.0(3)U5(1b)',
  '5.0(3)U5(1c)',
  '5.0(3)U5(1d)',
  '5.0(3)U5(1e)',
  '5.0(3)U5(1f)',
  '5.0(3)U5(1g)',
  '5.0(3)U5(1h)',
  '5.0(3)U5(1i)',
  '5.0(3)U5(1j)',
  '5.2(1)',
  '5.2(3)',
  '5.2(3a)',
  '5.2(4)',
  '5.2(5)',
  '5.2(7)',
  '5.2(9)',
  '5.2(9a)',
  '6.0(2)A1(1)',
  '6.0(2)A1(1a)',
  '6.0(2)A1(1b)',
  '6.0(2)A1(1c)',
  '6.0(2)A1(1d)',
  '6.0(2)A1(1e)',
  '6.0(2)A1(1f)',
  '6.0(2)A1(2d)',
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
  '6.0(2)A8(10)',
  '6.0(2)A8(10a)',
  '6.0(2)A8(11)',
  '6.0(2)A8(11a)',
  '6.0(2)A8(11b)',
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
  '6.0(2)U1(1)',
  '6.0(2)U1(1a)',
  '6.0(2)U1(2)',
  '6.0(2)U1(3)',
  '6.0(2)U1(4)',
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
  '6.0(2)U6(10)',
  '6.0(2)U6(10a)',
  '6.0(2)U6(1a)',
  '6.0(2)U6(2)',
  '6.0(2)U6(2a)',
  '6.0(2)U6(3)',
  '6.0(2)U6(3a)',
  '6.0(2)U6(4)',
  '6.0(2)U6(4a)',
  '6.0(2)U6(5)',
  '6.0(2)U6(5a)',
  '6.0(2)U6(5b)',
  '6.0(2)U6(5c)',
  '6.0(2)U6(6)',
  '6.0(2)U6(7)',
  '6.0(2)U6(8)',
  '6.0(2)U6(9)',
  '6.1(2)I1(2)',
  '6.1(2)I1(3)',
  '6.1(2)I2(1)',
  '6.1(2)I2(2)',
  '6.1(2)I2(2a)',
  '6.1(2)I2(2b)',
  '6.1(2)I2(3)',
  '6.1(2)I3(1)',
  '6.1(2)I3(2)',
  '6.1(2)I3(3)',
  '6.1(2)I3(3a)',
  '6.1(2)I3(4)',
  '6.1(2)I3(4a)',
  '6.1(2)I3(4b)',
  '6.1(2)I3(4c)',
  '6.1(2)I3(4d)',
  '6.1(2)I3(4e)',
  '6.1(2)I3(5)',
  '6.1(2)I3(5a)',
  '6.1(2)I3(5b)',
  '6.2(10)',
  '6.2(12)',
  '6.2(14)',
  '6.2(14a)',
  '6.2(14b)',
  '6.2(16)',
  '6.2(18)',
  '6.2(2)',
  '6.2(20)',
  '6.2(20a)',
  '6.2(22)',
  '6.2(2a)',
  '6.2(6)',
  '6.2(6a)',
  '6.2(6b)',
  '6.2(8)',
  '6.2(8a)',
  '6.2(8b)',
  '7.0(3)F1(1)',
  '7.0(3)F2(1)',
  '7.0(3)F2(2)',
  '7.0(3)F3(1)',
  '7.0(3)F3(2)',
  '7.0(3)F3(3)',
  '7.0(3)F3(3a)',
  '7.0(3)F3(3c)',
  '7.0(3)F3(4)',
  '7.0(3)F3(5)',
  '7.0(3)I1(1)',
  '7.0(3)I1(1a)',
  '7.0(3)I1(1b)',
  '7.0(3)I1(1z)',
  '7.0(3)I1(2)',
  '7.0(3)I1(3)',
  '7.0(3)I1(3a)',
  '7.0(3)I1(3b)',
  '7.0(3)I2(1)',
  '7.0(3)I2(1a)',
  '7.0(3)I2(2)',
  '7.0(3)I2(2a)',
  '7.0(3)I2(2b)',
  '7.0(3)I2(2c)',
  '7.0(3)I2(2d)',
  '7.0(3)I2(2e)',
  '7.0(3)I2(2r)',
  '7.0(3)I2(2s)',
  '7.0(3)I2(2v)',
  '7.0(3)I2(2w)',
  '7.0(3)I2(2x)',
  '7.0(3)I2(2y)',
  '7.0(3)I2(3)',
  '7.0(3)I2(4)',
  '7.0(3)I2(5)',
  '7.0(3)I3(1)',
  '7.0(3)I4(1)',
  '7.0(3)I4(1t)',
  '7.0(3)I4(2)',
  '7.0(3)I4(3)',
  '7.0(3)I4(4)',
  '7.0(3)I4(5)',
  '7.0(3)I4(6)',
  '7.0(3)I4(6t)',
  '7.0(3)I4(7)',
  '7.0(3)I4(8)',
  '7.0(3)I4(8a)',
  '7.0(3)I4(8b)',
  '7.0(3)I4(8z)',
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
  '7.0(3)I7(3z)',
  '7.0(3)I7(4)',
  '7.0(3)I7(5)',
  '7.0(3)I7(5a)',
  '7.0(3)I7(6)',
  '7.0(3)I7(6z)',
  '7.0(3)I7(7)',
  '7.0(3)IA7(1)',
  '7.0(3)IA7(2)',
  '7.0(3)IC4(4)',
  '7.0(3)IM3(1)',
  '7.0(3)IM3(2)',
  '7.0(3)IM3(2a)',
  '7.0(3)IM3(2b)',
  '7.0(3)IM3(3)',
  '7.0(3)IM7(2)',
  '7.0(3)IX1(2)',
  '7.0(3)IX1(2a)',
  '7.2(0)D1(1)',
  '7.2(1)D1(1)',
  '7.2(2)D1(1)',
  '7.2(2)D1(2)',
  '7.2(2)D1(3)',
  '7.2(2)D1(4)',
  '7.3(0)D1(1)',
  '7.3(0)DX(1)',
  '7.3(1)D1(1)',
  '7.3(2)D1(1)',
  '7.3(2)D1(1d)',
  '7.3(2)D1(2)',
  '7.3(2)D1(3)',
  '7.3(2)D1(3a)',
  '7.3(3)D1(1)',
  '7.3(4)D1(1)',
  '7.3(5)D1(1)',
  '8.0(1)',
  '8.1(1)',
  '8.1(2)',
  '8.1(2a)',
  '8.2(1)',
  '8.2(2)',
  '8.2(3)',
  '8.2(4)',
  '8.2(5)',
  '8.3(1)',
  '8.3(2)',
  '8.4(1)',
  '9.2(1)',
  '9.2(2)',
  '9.2(2t)',
  '9.2(2v)',
  '9.2(3)',
  '9.2(3y)',
  '9.2(4)',
  '9.3(1)',
  '9.3(1z)',
  '9.3(2)'
);

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , cbi,
  'cmds'     , make_list('show running-config')
);

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['feature_pim6'];

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
