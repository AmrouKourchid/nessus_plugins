#TRUSTED 8fa5df5b559be55395bb69f2566f4344b8efebfbf8127763d0c9e280dbb128caacee4fe2cf3a03922c2c02c6c5ba40f2f98190d5007fcd8224fd058ba915b770ee74754b4dfb54103ed03e0ca8f36e8c1754be92dc50b2b2f626783ce0d6433c7bcbb05247cc08c24537583e051609cff99762fb3b8931bc06e7ed5db88d1691bef9536a73c9bf99786daa32209f113becc1d8329f602929aba201855b775a23709fd248facd944cf5235d6ea9578e1014b5c8d07f2456faaa9960e99556f661ba0a723f97cc82440fc56b26c5b6ba02c16b14890e1aaea2b9e49fc42ca35625c57c5071efc807d9bff1a2b87360737c87025d657bc1bf0ccf2a5d4ead38e45aa34956b034e5279f503682f052407a50128391e7cb7c4708e9d264244dae09a3e2b279e41c99f6d1afea1b2aa27e35d6411dfa2a73fa4bc5ba97e11411afd085ed3cd3541b9315f00401f0ac6b01ea5045681085d6bfe59d5683300357af058853dad7175c121c177e9cd4782acbf19b34727b9dc428ad8e0a1e9cede71cdfd773a0a15e259cf5da117921d8def945d565f5f160cc536fa779a3f5b9bb77d544e74927d8b2bdc0d54da717581f35152db5e70841da2ad4c359300ab4c7b9d315a89bd53edb4d0224bf18eafc9c78e24d16705009807ea02b9e0930efb2e9654b2950e7aadbe6b5f0768fe247749affa3d06071b1346ff39b9be4260b506522f8
#TRUST-RSA-SHA256 12f6fb07762498f9cf8c57a2ad35db1d577562ef5061fe8495b7caa91ed1882e6bffa7200672e91a299949580327bf325abf61798dd7ac76e845fb9e957d8440c19f52e35e1a9e0942717fab4ab643aea61ab7ac5fa9c2623146afd471edba17f77e4cfcfae7451d1a5e2bc87ce7c35c075649db333a906caca1323521b80b5e09a72c9720a9a99d9def6914e6b86d7160f14da00e357f7bfe77d0ef0e198bb80a4e47b1e101f3457815be6765b34db4548c7ed207464a358f0bbbe5377c0607bb7cc9685647ef3bd2670cf30234b923f4a634c23d5004b1612f3b095944cdf3e6b513dc49d81a8def4bebd993fce8f4cbb591e78f4aaf6236a13b2fbf0881cbbed3c064ebd3f2fefe8f0bdcbefa9af6e732bfd10145cbd931de99b4834f1c5003bce8d407f1f6212e6d71738395445a15e8ead793d114f124d2a66b99fc766ad3637fb4b81581e06b62784b4377aed9684b4bb2be961c86799b3ef360a5b107f586ef5395ab53325fca21f56819a72a8afeb6780f97d7a32c1f041e661d1d347338938b5a3e865e59006d68dc0052e170d15eec65f2fb603ce677c5c389cfcb2a56242c7487860771de34952e75761ef56b881951c238f038665d0ded2bd034549749320e99ac8aa05a7fc5cf7c20d1a10a1a8a9690142a04945b951b68f32db3fd143192b5c2c1d31ddc9e917e1402ce15830429746286a1c47411625f65c9
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(131187);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/27");

  script_cve_id("CVE-2017-6663");
  script_bugtraq_id(99973);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvd88936");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170726-anidos");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/24");
  script_xref(name:"IAVA", value:"2023-A-0574-S");

  script_name(english:"Cisco IOS Autonomic Networking Infrastructure DoS (cisco-sa-20170726-anidos)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS is affected by a denial of service (DoS) vulnerability in the
Autonomic Networking feature. An unauthenticated, adjacent attacker can exploit this by replaying captured packets to
reset the Autonomic Control Plane (ACP) channel of an affected system in order to reset the ACP channel of an affected
system, causing autonomic nodes of an affected system to reload and stop responding.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170726-anidos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?89580ea2");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvd88936");
  script_set_attribute(attribute:"solution", value:
"No fixes are available. For more information, see Cisco bug ID(s) CSCvd88936.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-6663");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/22");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS');

version_list = make_list(
  '15.3(3)S2',
  '15.3(3)S6',
  '15.3(3)S1a',
  '15.3(3)S5',
  '15.3(3)S7',
  '15.3(3)S8',
  '15.3(3)S6a',
  '15.3(3)S9',
  '15.3(3)S10',
  '15.3(3)S8a',
  '15.2(3)E',
  '15.2(4)E',
  '15.2(3)E1',
  '15.2(3)E2',
  '15.2(3a)E',
  '15.2(3)E3',
  '15.2(3m)E2',
  '15.2(4)E1',
  '15.2(4)E2',
  '15.2(3)E4',
  '15.2(5)E',
  '15.2(3m)E7',
  '15.2(4)E3',
  '15.2(5)E1',
  '15.2(5b)E',
  '15.2(3m)E8',
  '15.2(3)E5',
  '15.2(4s)E2',
  '15.4(1)S',
  '15.4(2)S',
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
  '15.4(3)S0d',
  '15.4(3)S4',
  '15.4(3)S0e',
  '15.4(3)S5',
  '15.4(3)S0f',
  '15.4(3)S6',
  '15.4(3)S7',
  '15.4(3)S6a',
  '15.4(3)S8',
  '15.5(1)S',
  '15.5(2)S',
  '15.5(1)S1',
  '15.5(3)S',
  '15.5(1)S2',
  '15.5(1)S3',
  '15.5(2)S1',
  '15.5(2)S2',
  '15.5(3)S1a',
  '15.5(2)S3',
  '15.5(3)S2',
  '15.5(3)S3',
  '15.5(1)S4',
  '15.5(2)S4',
  '15.5(3)S4',
  '15.5(3)S5',
  '15.5(3)S6',
  '15.5(3)S6a',
  '15.5(3)S7',
  '15.5(3)S6b',
  '15.5(3)S8',
  '15.5(3)S10',
  '15.2(3)EA',
  '15.2(4)EA',
  '15.2(4)EA1',
  '15.2(5)EA',
  '15.2(4)EA4',
  '15.2(4)EA5',
  '15.2(4)EA6',
  '15.4(2)SN',
  '15.4(2)SN1',
  '15.4(3)SN1',
  '15.4(3)SN1a',
  '15.5(1)SN',
  '15.5(1)SN1',
  '15.5(2)SN',
  '15.5(3)SN0a',
  '15.5(3)SN',
  '15.6(1)S',
  '15.6(2)S',
  '15.6(2)S1',
  '15.6(1)S1',
  '15.6(1)S2',
  '15.6(2)S2',
  '15.6(1)S3',
  '15.6(2)S3',
  '15.6(1)S4',
  '15.6(2)S4',
  '15.6(1)T',
  '15.6(2)T',
  '15.6(1)T0a',
  '15.6(1)T1',
  '15.6(2)T1',
  '15.6(1)T2',
  '15.6(2)T0a',
  '15.6(2)T2',
  '15.6(1)T3',
  '15.6(2)T3',
  '15.6(2)SP',
  '15.6(2)SP1',
  '15.6(2)SP2',
  '15.6(2)SP3',
  '15.6(2)SP4',
  '15.6(2)SP3b',
  '15.6(2)SP5',
  '15.6(2)SP7',
  '15.6(2)SP8',
  '15.6(1)SN',
  '15.6(1)SN1',
  '15.6(2)SN',
  '15.6(1)SN2',
  '15.6(1)SN3',
  '15.6(3)SN',
  '15.6(4)SN',
  '15.6(5)SN',
  '15.6(6)SN',
  '15.6(7)SN',
  '15.6(7)SN1',
  '15.6(3)M',
  '15.6(3)M1',
  '15.6(3)M0a',
  '15.6(3)M1a',
  '15.6(3)M1b',
  '15.6(3)M2',
  '15.6(3)M2a',
  '15.6(3)M3',
  '15.6(3)M3a',
  '15.6(3)M4',
  '15.6(3)M5',
  '15.6(3)M6',
  '15.6(3)M7',
  '15.6(3)M6a',
  '15.6(3)M8',
  '15.7(3)M',
  '15.7(3)M1',
  '15.7(3)M3',
  '15.7(3)M2',
  '15.7(3)M4',
  '15.7(3)M5',
  '15.7(3)M4a',
  '15.7(3)M4b',
  '15.7(3)M5a',
  '15.7(3)M6',
  '15.8(3)M',
  '15.8(3)M0a',
  '15.8(3)M2',
  '15.8(3)M3',
  '15.8(3)M4',
  '15.9(3)M',
  '15.9(3)M1',
  '15.9(3)M0a',
  '15.8(3)M3b'
);

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['autonomic_networking'];

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvd88936',
  'cmds'     , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list,
  workarounds:workarounds,
  workaround_params:workaround_params
);
