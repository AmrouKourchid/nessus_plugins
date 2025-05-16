#TRUSTED a427596581074e48b2e92fd3898d26ee8b59e57adb8fc4563dd113f11888968de0dde6d6af46d7f2cec6fdd2315c45b080e88dafbc07e5e2acaaff55d4add70dcad6e3309d6497e55e37fdf4072cdf5df325bdcd02d39283bb72b852ef77c2b9a8380ace186f4d2e7d4fe2621962dabd8c0b5e6e378f93c21778cfecd54a651cef0d8b63d63f6de8d7da4ae02cecbfd5e35994188f30a5ff0afdc09edadb4f40ea8e34efa4a0e70be39dfb5192a1e6173e1f566f5454d68c59c313cfe2bd2e53db5b7c8a98b8f1dd9b05941f34ed4113561296fea17ce45c31f8198a32c93edf3028222d18f0ca752029bb0f975e0959b46532fb98968f68c4254825fa02d5eba783b96ec8991e7e0abb732c5d760e6fb4635e4459a81d7d1b51b4795bc020a1f009840a50d79da78558606eba1a2690669bca68150b57b7a92e3b2371f12225fcb81b1d0109af9b55230244e4a4872b91f54b1b59e87c8989bbc42da9c55b5a9022335edcbe0e49d6e282bccd8c96b7e66a93638fb968b5abb92a4333e205c200d94183347e283e07486d435353cbd7720f2b3a0a6e52d58d71e5271b03c58691e19bb3eed3b3897f619296cce956ea4fa92c9ccf6e1a2cd013754116ed5a44f99729b48802e0038a172d11a91169a92a578a3e438d2960366cae9247c176c675352b4002733966d335cbee78552883e579c0fbb787b6583d127fef998cf164
#TRUST-RSA-SHA256 8caab743c55cee7a61295e1fdbea373ee8bd95abb0b98b8df8cd7b35e20d4a0760cf9895187b7f0455c47447b2f73f8ecc575196efec7d9409be5e3ea5c1d450dc61fbaa8c6528a49b18d9f383cafc832dfd415995345c17cf542e951cf5699e2ff792aa49956ad4f5bde780b7901b502194d76a6c7aef5425889bf957d99b7d380a18079d2c8f3f815e2fd94497dd01feeeff07d622d085b33560de7057f41b8e5b8a28782f822e0b97ec7f3d09048d9567a23d91bdf7ac2891ecdf415a1dea5a8c731d0c7d2caf071e8d3047769a5004bce0096bb843e2099b6ae0c56766f3236f6fe0b762e6dcedbec85438e03efc4c443e0c6346d5f51f2fab662255c9f696edbaf06f50ee4bce1025548a02eddb9993cdc22bdede6570e994a4b3f13dc151f9643d0476949fcc81cbc291a2cd6f78a800b4d52f7e63e83edd5f73555ca99d9d2dc04758930192ae6e08af3aa94fb58d9732333773c6838ef430022ac21ae636960da089943d7136be6e7d1acf0da495e82b80c5b5d9de13cbcc896277bc97f71c458e3b8e0a32a943222a72f9240fd1348bdd5ae610d60912bca355759cb789dfc2c78e5c36eeb24b4e05ee7dd2c4458d5958a12f2e7e5f54f33106ab3c67590e42072a1242a5da77382f048a9272560e41d4bcd6dde9ddc01b96102d2bec387a6482939d877df1e0446ca4ed0f2d3706d5013c5d1f2faa66a402e351c4
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(137184);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/04");

  script_cve_id("CVE-2020-10136");
  script_xref(name:"CISCO-BUG-ID", value:"CSCun53663");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt66624");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt67738");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt67739");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt67740");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu03158");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu10050");
  script_xref(name:"CISCO-SA", value:"cisco-sa-nxos-ipip-dos-kCT9X4");
  script_xref(name:"IAVA", value:"2020-A-0233");
  script_xref(name:"CEA-ID", value:"CEA-2020-0049");

  script_name(english:"Cisco NX-OS Software Unexpected IP in IP Packet Processing Vulnerability (cisco-sa-nxos-ipip-dos-kCT9X4)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco NX-OS Software is affected by a denial of service vulnerability in
the network stack due to the affected device unexpectedly decapsulating and processing IP in IP packets that are
destined to a locally configured IP address. An unauthenticated, remote attacker can exploit this issue by sending a
crafted IP in IP packet to an affected device, to bypass certain security boundaries or cause a denial of service
condition on an affected device.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nxos-ipip-dos-kCT9X4
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0f50ed05");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCun53663");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt66624");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt67738");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt67739");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt67740");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu03158");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu10050");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version or apply the workaround referenced in Cisco bug IDs CSCun53663, CSCvt66624,
CSCvt67738, CSCvt67739, CSCvt67740, CSCvu03158 and CSCvu10050 or alternatively apply the workaround mentioned 
in the advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-10136");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/05");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl", "cisco_enum_smu.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Model", "Host/Cisco/NX-OS/Device");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco NX-OS Software');

cbi = '';

if ('Nexus' >< product_info.device)
{
  if (product_info.model =~ "^10[0-9][0-9]"){
    cbi = 'CSCvu10050, CSCvt67738';
    version_list = make_list(
      '5.2(1)SK3(1.1)',
      '5.2(1)SK3(2.1)',
      '5.2(1)SK3(2.1a)',
      '5.2(1)SK3(2.2)',
      '5.2(1)SK3(2.2b)',
      '5.2(1)SM1(5.1)',
      '5.2(1)SM1(5.2)',
      '5.2(1)SM1(5.2a)',
      '5.2(1)SM1(5.2b)',
      '5.2(1)SM1(5.2c)',
      '5.2(1)SM3(1.1)',
      '5.2(1)SM3(1.1a)',
      '5.2(1)SM3(1.1b)',
      '5.2(1)SM3(1.1c)',
      '5.2(1)SM3(2.1)',
      '5.2(1)SV3(1.1)',
      '5.2(1)SV3(1.10)',
      '5.2(1)SV3(1.15)',
      '5.2(1)SV3(1.2)',
      '5.2(1)SV3(1.3)',
      '5.2(1)SV3(1.4)',
      '5.2(1)SV3(1.4b)',
      '5.2(1)SV3(1.5a)',
      '5.2(1)SV3(1.5b)',
      '5.2(1)SV3(1.6)',
      '5.2(1)SV3(2.1)',
      '5.2(1)SV3(2.5)',
      '5.2(1)SV3(2.8)',
      '5.2(1)SV3(3.1)',
      '5.2(1)SV3(3.15)',
      '5.2(1)SV3(4.1)',
      '5.2(1)SV3(4.1a)',
      '5.2(1)SV3(4.1b)',
      '5.2(1)SV5(1.1)',
      '5.2(1)SV5(1.2)',
      '5.2(1)SV5(1.3)'
      );
  }

  if (product_info.model =~ "^3[0-9]{3}")
  {
    cbi = 'CSCun53663';
    version_list = make_list(
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
      '6.1(2)I2(2a)',
      '6.1(2)I2(2b)',
      '6.1(2)I3(1)',
      '6.1(2)I3(2)',
      '6.1(2)I3(3)',
      '6.1(2)I3(3a)',
      '7.0(3)I1(1)',
      '7.0(3)I1(1a)',
      '7.0(3)I1(1b)',
      '7.0(3)I1(1z)'
    );
  }

  if (product_info.model =~ "^5[56][0-9][0-9]"){
    cbi = 'CSCvt67739';
    version_list = make_list(
      '5.2(1)N1(1)',
      '5.2(1)N1(1a)',
      '5.2(1)N1(1b)',
      '5.2(1)N1(2)',
      '5.2(1)N1(2a)',
      '5.2(1)N1(3)',
      '5.2(1)N1(4)',
      '5.2(1)N1(5)',
      '5.2(1)N1(6)',
      '5.2(1)N1(7)',
      '5.2(1)N1(8)',
      '5.2(1)N1(8a)',
      '5.2(1)N1(8b)',
      '5.2(1)N1(9)',
      '5.2(1)N1(9a)',
      '5.2(1)N1(9b)',
      '6.0(2)N1(1)',
      '6.0(2)N1(1a)',
      '6.0(2)N1(2)',
      '6.0(2)N1(2a)',
      '6.0(2)N2(1)',
      '6.0(2)N2(1b)',
      '6.0(2)N2(2)',
      '6.0(2)N2(3)',
      '6.0(2)N2(4)',
      '6.0(2)N2(5)',
      '6.0(2)N2(5a)',
      '6.0(2)N2(5b)',
      '6.0(2)N2(6)',
      '6.0(2)N2(7)',
      '7.0(0)N1(1)',
      '7.0(1)N1(1)',
      '7.0(2)N1(1)',
      '7.0(3)N1(1)',
      '7.0(4)N1(1)',
      '7.0(4)N1(1a)',
      '7.0(5)N1(1)',
      '7.0(5)N1(1a)',
      '7.0(6)N1(1)',
      '7.0(6)N1(2s)',
      '7.0(6)N1(3s)',
      '7.0(6)N1(4s)',
      '7.0(7)N1(1)',
      '7.0(7)N1(1a)',
      '7.0(7)N1(1b)',
      '7.0(8)N1(1)',
      '7.0(8)N1(1a)',
      '7.1(0)N1(1)',
      '7.1(0)N1(1a)',
      '7.1(0)N1(1b)',
      '7.1(1)N1(1)',
      '7.1(1)N1(1a)',
      '7.1(2)N1(1)',
      '7.1(2)N1(1a)',
      '7.1(3)N1(1)',
      '7.1(3)N1(2)',
      '7.1(3)N1(2a)',
      '7.1(3)N1(3)',
      '7.1(3)N1(4)',
      '7.1(3)N1(5)',
      '7.1(4)N1(1)',
      '7.1(4)N1(1a)',
      '7.1(4)N1(1c)',
      '7.1(4)N1(1d)',
      '7.1(5)N1(1)',
      '7.1(5)N1(1b)',
      '7.2(0)N1(1)',
      '7.2(1)N1(1)',
      '7.3(0)N1(1)',
      '7.3(0)N1(1a)',
      '7.3(0)N1(1b)',
      '7.3(1)N1(1)',
      '7.3(2)N1(1)',
      '7.3(2)N1(1b)',
      '7.3(2)N1(1c)',
      '7.3(3)N1(1)',
      '7.3(4)N1(1)',
      '7.3(4)N1(1a)',
      '7.3(5)N1(1)',
      '7.3(6)N1(1)',
      '7.3(6)N1(1a)',
      '7.3(7)N1(1)',
      '7.3(7)N1(1a)'
      );
  }

  if (product_info.model =~ "^60[0-9][0-9]"){
    cbi = 'CSCvt67739';
    version_list = make_list(
      '6.0(2)N1(1)',
      '6.0(2)N1(1a)',
      '6.0(2)N1(2)',
      '6.0(2)N1(2a)',
      '6.0(2)N2(1)',
      '6.0(2)N2(1b)',
      '6.0(2)N2(2)',
      '6.0(2)N2(3)',
      '6.0(2)N2(4)',
      '6.0(2)N2(5)',
      '6.0(2)N2(5a)',
      '6.0(2)N2(5b)',
      '6.0(2)N2(6)',
      '6.0(2)N2(7)',
      '7.0(0)N1(1)',
      '7.0(1)N1(1)',
      '7.0(2)N1(1)',
      '7.0(3)N1(1)',
      '7.0(4)N1(1)',
      '7.0(4)N1(1a)',
      '7.0(5)N1(1)',
      '7.0(5)N1(1a)',
      '7.0(6)N1(1)',
      '7.0(6)N1(2s)',
      '7.0(6)N1(3s)',
      '7.0(6)N1(4s)',
      '7.0(7)N1(1)',
      '7.0(7)N1(1a)',
      '7.0(7)N1(1b)',
      '7.0(8)N1(1)',
      '7.0(8)N1(1a)',
      '7.1(0)N1(1)',
      '7.1(0)N1(1a)',
      '7.1(0)N1(1b)',
      '7.1(1)N1(1)',
      '7.1(1)N1(1a)',
      '7.1(2)N1(1)',
      '7.1(2)N1(1a)',
      '7.1(3)N1(1)',
      '7.1(3)N1(2)',
      '7.1(3)N1(2a)',
      '7.1(3)N1(3)',
      '7.1(3)N1(4)',
      '7.1(3)N1(5)',
      '7.1(4)N1(1)',
      '7.1(4)N1(1a)',
      '7.1(4)N1(1c)',
      '7.1(4)N1(1d)',
      '7.1(5)N1(1)',
      '7.1(5)N1(1b)',
      '7.2(0)N1(1)',
      '7.2(1)N1(1)',
      '7.3(0)N1(1)',
      '7.3(0)N1(1a)',
      '7.3(0)N1(1b)',
      '7.3(1)N1(1)',
      '7.3(2)N1(1)',
      '7.3(2)N1(1b)',
      '7.3(2)N1(1c)',
      '7.3(3)N1(1)',
      '7.3(4)N1(1)',
      '7.3(4)N1(1a)',
      '7.3(5)N1(1)',
      '7.3(6)N1(1)',
      '7.3(6)N1(1a)',
      '7.3(7)N1(1)',
      '7.3(7)N1(1a)'
      );
  
  }

  if (product_info.model =~ "^70[0-9][0-9]")
  {
    cbi = 'CSCvt66624';
    smus['7.3(6)D1(1)'] = 'CSCvt66624';
    version_list = make_list(
      '5.2(1)',
      '5.2(3)',
      '5.2(3a)',
      '5.2(4)',
      '5.2(5)',
      '5.2(7)',
      '5.2(9)',
      '5.2(9a)',
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
      '6.2(24)',
      '6.2(2a)',
      '6.2(6)',
      '6.2(6a)',
      '6.2(6b)',
      '6.2(8)',
      '6.2(8a)',
      '6.2(8b)',
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
      '7.3(6)D1(1)'
    );
  }

  if (product_info.model =~ "^90[0-9][0-9]")
  {
    cbi = 'CSCun53663';
    version_list = make_list(
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
      '7.0(3)I1(1)',
      '7.0(3)I1(1a)',
      '7.0(3)I1(1b)',
      '7.0(3)I1(1z)'
    );
  }
}

if (empty_or_null(cbi)) audit(AUDIT_HOST_NOT, 'an affected model');

if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info.version,
  'bug_id'   , cbi,
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list,
  switch_only:TRUE,
  smus:smus
);

