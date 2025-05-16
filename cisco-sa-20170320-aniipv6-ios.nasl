#TRUSTED 31232e55736e31b90fbf5a6f27b965e8f6bf4d1128a9b7bf4862f3ca021c63b5fe6c9a55cdcb272194e47fb7e0f6cb3fdd72004a869b5a50f3c76078592c1e1e3a2f8dabe48e8f9a37c7f3f5ee213e73c8a1f3618e73c8de1a917232b1f5ddad277b5acc76c9f22c7397cfb19967bfbc0726626e175328c2be07759993957f5b7af504d3c520eb76ec844eb792a9496b3bae2df317d51e54795c91ac4e405e0329f16a21d72565e4afd03f4a7a46746920dda48de871f15f9fb26ced80c3fdd0d29943486086b2204086a21e31b11f004d28451037dc05934f354e90966487e1e88d981f52b9b09a8c32223ff577bea22fd87803163439d275160882b1799953554aba04a125580573577913a1a2424cbf7a3fdcc06a5302c93718e85f744384bad4b5ce0ddceeeeb79bb4148cb50c996fab90ec0c3c534db9f34fa0cc535521c4422d487344a06762228b1e13fb91853a4a10d7f1c3505833285b754d0a97e5af2e86167d1cd8f014c9c70e062a1f6e822c18560c9321942f24fdb435aef739a8dbe8ba537559cd60d97670741d1bb056deb133b7c8b66d6bf4d1e58a8aa655c2b9b746383ecb16da99b5d13af1f161917c1402dfe3efc0978e4066d44543283b559b4c7cbb589bb25d8d1d86d23b5df8601367b675c34a1e50948416bf405af7c43a7d3f4dba4b3c5e3c9b997c40a65287fdbf7b2e7b69e1e7a58cba0e6758
#TRUST-RSA-SHA256 3e6a280e79b09c92f1a8378dc99b5afe24eddd7304b69e5d80f1dd404ad9eecbacf86ad7ec3c60afed98ab1403073fad238e78480b2a44bc8425dd58f8d71ff87beee7a13cab616205fc9dfea670b1a5aa02111edffe35fa62941a5b7a7a17eb8073045056041aeff9101dc32ae9c02ee7040b36db2204c414d2c68c35b6255cb4e4de2a7c7218dc94c0b269c3c567f34c02e06e2f94e9e5e4c300d685289641acc28b47e5465e8f892913628aa7cb058a8e263d432b1f99643cdd0da5db4882c756945add95688971956a8e9acae291021b20e385762bde16c4d161d9acc82b70820cc0a47dcb6d87abf032061ed2db4b5e1f690bd6ecab96d2d3b9f8fa571e915b131b6bd78fecab85e376bd032857666767f761ebc1e9bd62b8c64d2787d802ffbcaaca5eaa8f5abb0af15ed70c8574bb3d414330da7f609c07b56f9559e00d8dee872629d50c6591dec33677ce626b04b663042a711eec69de6b112261dcb7db3a0dbc7d6c1df596f87be4722a2c3f76ac1a282068a2dd81dddf9846fcdc76ef2920af43ba07d6438db12a48e1711135af7aeaa0466f2308443cf452595bb5dc9c96c0c7f4775cfc1bf4dc360a2617a13f65fe637cc3faf82b0c331d99bf8bdeb52055e7d90eb7364b93ebb2805ca9dc8bf8f74611701350f53af108e64335482727ad1ae5af2093a6c3baf090ea9896498a9c1151d99da9ec3c7c052a68
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97945);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/18");

  script_cve_id("CVE-2017-3850");
  script_bugtraq_id(96971);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvc42729");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170320-aniipv6");

  script_name(english:"Cisco IOS ANI IPv6 Packets DoS (cisco-sa-20170320-aniipv6)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS software running
on the remote device is affected by a denial of service vulnerability
in the Autonomic Networking Infrastructure (ANI) component due to
incomplete input validation of certain crafted IPv6 packets. An
unauthenticated, remote attacker can exploit this issue, via specially
crafted IPv6 packets, to cause the device to reload.

Note that this issue only affect devices with ANI enabled that have a
reachable IPv6 interface.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170320-aniipv6
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8d249229");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20170320-aniipv6.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-3850");
  script_set_attribute(attribute: "cvss3_score_source", value: "manual");
  script_set_attribute(attribute:"cvss3_score_rationale", value:"Scoring adjustsed to align with CVSS 3.1 attack complexity guidance.");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/24");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}

include("audit.inc");
include("cisco_workarounds.inc");
include("ccf.inc");

product_info = cisco::get_product_info(name:"Cisco IOS");

version_list = make_list(
  '15.3(3)S',
  '15.3(3)S1',
  '15.3(3)S2',
  '15.3(3)S3',
  '15.3(3)S6',
  '15.3(3)S4',
  '15.3(3)S5',
  '15.2(3)E',
  '15.2(4)E',
  '15.2(3)E1',
  '15.2(3)E2',
  '15.2(3)E3',
  '15.2(4)E1',
  '15.2(4)E2',
  '15.2(5)E',
  '15.2(5b)E',
  '15.4(1)S',
  '15.4(3)S',
  '15.4(1)S1',
  '15.4(1)S2',
  '15.4(2)S1',
  '15.4(1)S3',
  '15.4(3)S1',
  '15.4(2)S2',
  '15.4(3)S2',
  '15.4(3)S3',
  '15.4(1)S4',
  '15.4(2)S3',
  '15.4(2)S4',
  '15.4(3)S4',
  '15.4(3)S5',
  '15.4(3)S6',
  '15.5(1)S',
  '15.5(2)S',
  '15.5(1)S1',
  '15.5(3)S',
  '15.5(1)S2',
  '15.5(1)S3',
  '15.5(2)S1',
  '15.5(2)S2',
  '15.5(3)S1',
  '15.5(3)S1a',
  '15.5(2)S3',
  '15.5(3)S2',
  '15.5(3)S0a',
  '15.5(3)S3',
  '15.5(1)S4',
  '15.5(3)SN',
  '15.6(1)S',
  '15.6(2)S',
  '15.6(2)S1',
  '15.6(1)S1',
  '15.6(1)S2',
  '15.6(1)T',
  '15.6(2)T',
  '15.6(1)T0a',
  '15.6(1)T1',
  '15.6(2)T1',
  '15.6(1)T2',
  '15.6(2)T2',
  '15.6(2)SN',
  '15.6(3)M'
  );

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['ipv6_enabled'];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , "CSCvc42729",
  'cmds'     , make_list("show running-config")
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
