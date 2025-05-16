#TRUSTED 097dc3d1dd4192c56321fe9af7b5cdf58eecd0bda6704f1b9cbbe2c4f19aac811e6a0eeeda782324d6ffd7549ab85bbd56d67dc698d54c501ccada10c838a9217104865ec1c79ac85593cce7d304fb2c8cfd6fa000a11e95379d0c05d8e690ae7d141f7843f27116b4844148193ed141b53466ac83d01c5c81360d9659cce350c0a412d0cf9d19bf1c958f07c469f46b54ba06e19844ff6d03b957f0b1c1a54bfe91d407286707aadea2806cdf3f983c92dd730f6948a7843e477f442b3f2fab23b9d8a8ab2ed527e21555f50446ad4852aea2263d6b428cc297cf8703cc42b784816c18aeaf6923040e1449453e38cbdc39622555791b2fc4230f255b07e444879f3f3915d322a67bcc65ab53e09ccc2d1168ca6a47ca60980734807e2d5f4d93f14cb8a2a894e8cac8f584d3b4e2a68369616e6c75c8f0b6b590287643496448be5f8f8932bb95726a8d6db2d5478d50c3fd831bf83ed48579dc2075196da2c1a7ff1d8ece42758220f296dd0c5a5cb706bbf9ae69d29beb45f8b9eb92a8921e20f9e61435896ea10c787755d98ce37015c0cda9ae02745f26126bc4bb1fcadba268a8ca3d561f641a1983e52dd52ca5826dd4167a256186a90cc87a004b8734eb1c21679e40e8b902dfad9a0568c7695c540e62f7530951c05040c227e45ce7554a273abcdb9e5af2340173f4a72bf49c3487bdc4635e4f612d71d0d08975
#TRUST-RSA-SHA256 22491ee1d665b789cba0ab02075e43c672ac3b7c821242802e7f97874e77578ee11800d62e8946317bcb60cae2125ca4d40aa3cb34360114b1ddc3336d09914eae05e7a31c8c20e75c791c653127db9001ee36dc568ee4853995b748d8d22f95131c71454e22a8f6fc9fedf485f21208db4b8741e8192756a6e74ec3574dca9798583dc48dc8f3eea7f55240a7f2b25342df085ea054a7798e98cbb043d14f75aed3316061b1201f4a3aed59ceebf7c78d4979e224f2f8d79f807debe130db1df31713970df2ac60e606054e6adeaf39e99d8e55cbb7481b79c949f2aa4f8bcce5c52236489abf963576abb679f79c86aae3a3c5ca6d38fc16593f98f2f3d33db0f4982534a42c36ecf379e63de6d876b4ec9e1e2829f3922414825976e7c8cfbb4b26842030dba9d5a5d5b68d8473f7807718622247c1f1f9d4188511ca583db22fcd1ab0c154f377a6cae9165bf6635360a3a4cb6146c956cdacb114989c142de51521cc93065261d5b238d4f99eb0f3b3cb81ab9bb7a05d95bccbdeae911abb295bb9f410234ee3da5a7a14256c0034f151acf217a4dfce53df0eec90e51b1530072b13dae17736fa46be83f1b119ff4a5ce9737f59c3383da8a66b3d2b489b8e4a22e33c158ab6ccacddd27dd1b13f98ec6e9e7ad2006a0500bd1f47b700d1ad3af71073c9d4d9263dde5b3e3b5105553c3cabdb3a459c59a5f14233cfce
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(140131);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/08");

  script_cve_id("CVE-2020-3398");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr60479");
  script_xref(name:"CISCO-SA", value:"cisco-sa-nxosbgp-mvpn-dos-K8kbCrJp");
  script_xref(name:"IAVA", value:"2020-A-0394-S");

  script_name(english:"Cisco NX-OS Software Border Gateway Protocol Multicast VPN Session DoS (cisco-sa-nxosbgp-mvpn-dos-K8kbCrJp)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco NX-OS Software is affected by a vulnerability in the Border Gateway
Protocol (BVP) Multicast VPN (MVPN) implementation due to incorrect parsing of a specific type of BGP MVPN update
message. An unauthenticated, remote attacker can exploit this, by sending this BGP MVPN update message, in order to
cause a partial denial of service (DoS) condition due to the BGP session being down.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nxosbgp-mvpn-dos-K8kbCrJp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?07d34ac4");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74239");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr60479");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvr60479");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3398");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/02");

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

version_list=make_list(
  '7.0(3)F3(1)',
  '7.0(3)F3(2)',
  '7.0(3)F3(3)',
  '7.0(3)F3(3a)',
  '7.0(3)F3(3c)',
  '7.0(3)F3(4)',
  '7.0(3)F3(5)',
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
  '7.0(3)IM7(2)',
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

workarounds = make_list(CISCO_WORKAROUNDS['show_running-config']);
workaround_params = {'pat':make_list('address-family ipv(4|6) mvpn', 'feature ngmvpn'), 'require_all_patterns':TRUE};

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvr60479',
  'cmds'     , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list,
  workarounds:workarounds,
  workaround_params:workaround_params
);



