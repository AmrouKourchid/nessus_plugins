#TRUSTED 5659f6df60d3d8070ef2ecdccfb161d9246637a58db94e1839f18ce311ec811629c191618e84c7bfa828d11f6b9b96481438a5f9fd71612a5693092e0e25ba3b507a52c87cedc15d311dfdcda309f9c0f4d60db3f74551f567adbd773c4db43eb7d0abb7fd41d2fae4196ad5233a18ac11469f2a771a8678508dba90ff1661207cb56280f99b4551b3e7bdb427aef7822cdc13768c5f79f3773fefc863581ffbb1aeb97a6438303e7219401a109681bf27987a6dec95c0e62f170f3dac0fe8b4351571dfb97526024792ca3037ffa68372f46c4e9f4273fb295c6aae9f5ad93b625ab3cb7c12af50f749060c9b2b62543885c24827dadb782089b940730e3b88ae8e28861e3b95ee84202006061769afc957e18a90df563828a4d248b6d4004d5d73b683e9cbab578e062b3bb48d25910e744557b9e878b9ebfaaec8fe56f30c02c919960a8b5f06c759c4aa0ebaf435234ffca81838d7947f1841df0f019b34c7862c9102ddbbbce497a2062da1ec53d2957b40151d15c825d7434dae5e2ab9c7519d244925f1deb144e731422e29a9ddab5573133f74cfea7e5c18e9b4218d6c56da70809376b593acf6ace7a6419fb0d2537c5cad7f9986a4b03882f539dbbad74bae52d707d0351a787e7219119db603c44a2c15cc395f07555e64c3cb256ca2551f5104c17dbb8adb7e9577fd4e892929d49711d4ab538831dd872e679e
#TRUST-RSA-SHA256 0657c90c57a7f4f00955bd0263db4b61111643f73a4047658030e9f3d548b33fc076519c7ba6b9e084d9218476bc2eedf4a058c39afa6d5e24905a7b9065e7e26baebb2a0530165b76a4e47403d9a352400fbe237bea676ad9aaa6790cd3d9282cd2d7d383cec4abebfb899fd3e28ea69a19247766cd68df008eaf2225ec2c879001f7acb51ad28e5f4b1ce476387ff4b5021ab16efff40b6dd184d07e132a54c53028e7b6c0b0a89f115ca94d4aee7ef3a5dfdbddd502fbc75653875a0a48c1a57ed629d71d7bb538e691e40579d3869103abd809e3e1adcf44bbdf89e00e749deaff887e1c306b90df5eb40c1f5f0b37fd4e70632325ee3066fc3877a5309c59bcfd6a14c12fd333f8c8e495e76d6c1765fc3fa2ee3109c43a2d5f223c51701bf0a0de5f9b3fdb6efc5e09502c70e511f9138b3424bae8620d69da87e0b5b860e51c2ac9800a105dbb5e0203426db3ffa1d3e2e371cca74d6b1f6b1dc5636af74ea1995fe9c2d5793926d7c1ce13597f9466347fe4fec161a1b04ae146714cd1f21cef89070c8e400168299551b909d30a1a862f4608556c7b291bb379089dd321437eb7e0b145004ffc8924c6722998edfbaf648ea3517dd22e0150e6b2e96aa8491abfa3a334bf59b853df4b7a85c030d23f98eb78632cd0c609d7df5c8c2e4f07547f15928190f7ed9eedad2b70f8f7afff7e0bbcefd9c617c42e6afd1f
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148091);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2021-1381");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu78908");
  script_xref(name:"CISCO-SA", value:"cisco-sa-XE-BLKH-Ouvrnf2s");

  script_name(english:"Cisco IOS XE Software Active Debug Code (cisco-sa-XE-BLKH-Ouvrnf2s)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS-XE Software is affected by a vulnerability. Please see the included
Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-XE-BLKH-Ouvrnf2s
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fd603840");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu78908");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvu78908");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1381");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(489);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/24");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

model = toupper(product_info.model);
    
# Vulnerable model list
if (model !~ '^IR1101')
    audit(AUDIT_HOST_NOT, 'affected');

version_list=make_list(
  '16.11.1',
  '16.11.1a',
  '16.11.1b',
  '16.11.1c',
  '16.11.1s',
  '16.11.2',
  '16.12.1',
  '16.12.1a',
  '16.12.1c',
  '16.12.1s',
  '16.12.1t',
  '16.12.1w',
  '16.12.1x',
  '16.12.1y',
  '16.12.1z',
  '16.12.1za',
  '16.12.2',
  '16.12.2a',
  '16.12.2s',
  '16.12.2t',
  '16.12.3',
  '16.12.3a',
  '16.12.3s',
  '16.12.4',
  '16.12.4a',
  '17.1.1',
  '17.1.1a',
  '17.1.1s',
  '17.1.1t',
  '17.1.2',
  '17.2.1',
  '17.2.1a',
  '17.2.1r',
  '17.2.1v',
  '17.2.2',
  '17.2.3'
);

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_NOTE,
  'bug_id'   , 'CSCvu78908',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
