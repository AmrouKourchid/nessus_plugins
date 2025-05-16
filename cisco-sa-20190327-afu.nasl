#TRUSTED 3abb33d068118d7ede724eb854afa0e79ce787dff5f1b4bcb82a0e463f6a5385fe1f3d0a31bedf5151b2c66af28c8a693811d54404b082804dd082d5ccee56048304e6e35a8ba3ecb27efd682485f0993f0d9b955d9d0c5c2c6e89f397e5f9872a60141ce68daa3e815ce6773b1f78420fe130104eb9d131e302b18e117b2fb596acb2b90db48fd69df3a99e80d9fb9582b69680c27b018436f39eaa784ccb5981f4e50c0437c335ae5227a14d943fbab46a70b7d1d832227d043abd9f66f290dda77c31c3531684c9491bfb54894b1e9ca60b6bd4193e2454c5420c4a85f2568f4b21b62fb6b1e907d2ca6dd8b46f84ab1774be72ac2a2f67f82370aad45f193f75ff7eafe6f3733cc6a858a83d5f0fa23d49b39e296b84474e5763b5949de9343db66e26d58183820915f502d988399528571880e05f4f71764a80770322f310b34326b3b4b44d85cdaeb182660e35c08b834e742ccdde7ee0ef7c1c0e0fdf961fe718c1d82a1f44daafc69f60d21b3f88111a8962ce68191b2380252952309ff58149f20f3679ba0dfb591e65f43d3da3ae80d03fff2a7ee507056d304d977ec5a4f16cb402b7460c790cb1760789cbc95122a92e88874bebf4c32fd2dbf31b88c8740c93410e95b573916bc28e52ba803cd4d161f00d758afde31a0506007455dacc7d511357345227a05d320bc9ec7d5e061df89c298d5a954b3055b2ab
#TRUST-RSA-SHA256 1b151c936161e2c88faa958a5169999fe381673b55c485bffd1a4cb450f28b082828d65ec1240613f3ebd002d192b8d6d30d5492ef52afe5f1833354e3c25035fa004a84f17d3f4e945ab44e62d66abe8112ed335a1674e262fbcd421865ff6887348e653ab47fbfc793dc6237cc3e8cea4d6568e457d9ef5fa39890ae058bc92c75ec40b17ee0aa4d99ecfa299bef35794986b67e66e5c3bf4fbfa5b467aaeb74f20bbb5efe3e57fccae1be586debf6ded0b522b695fefcdb54205b142140c9abb6431be52ea864a21c709173f31bf93252fea9e94d714bd255bca2bed34fad3172843ffa74f7305094e231625ccc71653945a69c3ab7403011038632051a722ef6e9195d62046a6d4a1a8c6c9b64d9505f598b2d2a172db860b806b5580479bf086cdb66e1239463727558ee07dc92168b71e878565c3531d63788ae0813bb3be0c01cba15b88cf4f588ba8983d7535674a33f3c936e5b63eaffd641fbf95475a0abd7b938a69091fea59a173be520e5309788fe6249d8a2e60ecc6e028cb7133bb005744f6f55d64a2a2717a75227f9b61192126bdee1f939b3c0ffc2b13004d36d34ef967655a1f6d9efa37810d6eb063331ac3aba11cde80aa2f097e79fce6a1959e5d73fb537e1e72cf3025ce195db8669adf3ec4a4656f34024edc869fe0894dc2e445ea1bc7d0de55109a039cea060e3af54c6955fc292211c893260
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(124589);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2019-1743");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi48984");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190327-afu");

  script_name(english:"Cisco IOS XE Software Arbitrary File Upload Vulnerability");
  script_summary(english:"Checks the version of Cisco IOS XE Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a vulnerability in the web UI framework of
Cisco IOS XE Software could allow an authenticated, remote attacker to make unauthorized changes to the filesystem of the
affected device.The vulnerability is due to improper input validation. An attacker could exploit this vulnerability by
crafting a malicious file and uploading it to the device. An exploit could allow the attacker to gain elevated privileges
on the affected device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190327-afu
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8f275e4c");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-71135");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi48984");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvi48984");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1743");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/03");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_workarounds.inc");
include("ccf.inc");

product_info = cisco::get_product_info(name:"Cisco IOS XE Software");

version_list=make_list(
  '16.8.1s',
  '16.8.1e',
  '16.8.1d',
  '16.8.1c',
  '16.8.1b',
  '16.8.1a',
  '16.8.1',
  '16.7.1b',
  '16.7.1a',
  '16.7.1',
  '16.6.3',
  '16.6.2',
  '16.6.1',
  '16.5.3',
  '16.5.2',
  '16.5.1b',
  '16.5.1a',
  '16.5.1',
  '16.4.3',
  '16.4.2',
  '16.4.1',
  '16.3.6',
  '16.3.5b',
  '16.3.5',
  '16.3.4',
  '16.3.3',
  '16.3.2',
  '16.3.1a',
  '16.3.1',
  '16.2.2',
  '16.2.1'
);

workarounds = make_list(CISCO_WORKAROUNDS['HTTP_Server_iosxe']);
workaround_params = make_list();

reporting = make_array(
'port'     , product_info['port'], 
'severity' , SECURITY_WARNING,
'version'  , product_info['version'],
'bug_id'   , 'CSCvi48984'
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
