#TRUSTED 0b179dd9159325afaf2d2da4ec6aa5590582cf79f037ceea563ce0967232ca8e1edc18fa153e2ec483d4ef19e3f62a2f06a0a5e03e9ad605a6d88bae64d40ce5bda3de9d7350820cd46ce1bf2cc8334294d830942dd272fcf8156aa42a2a2f71e6abb2e64c22f3c50c84d061685dd61d2f5ad29ba45adbe64d866e2d87861764505a85ace0ffbf633b8f216c6623d3b736b71e302216df78f1e045126b94d4c205f4f12a8a5a5520e2461eec5c413f7fbd0ccb906a63ec01767ca54c1d4e8e9489e70a2840a54b93619cfb6498947c61412523609a74cf67de896c7ed151483dee4d9220e1863f795996953c9fe5ed98dac936c93db4f460b280358e26830eee744ded19cd7eedfd7cd56a3f1bea45771e64fbe8c282526a04ac1f6bc9d76405be9e3d90eeeb45092c1b0ac56376c5c9076049c4203e9a30996395d25b14d2c85ab42cbdb1accc93657985d34aed2693585e2f30ad1624d3218150a81593adec1bb0749c62f77f152ef768021f3789e096a805d3e5f50e28e3a8c1e65b8a5ae1a4e117096db02b4b42d62419cc4509a473888fd6c57e0ba9a279f23ae6471ed206f13c5e3d1fe53676d55247081fea5e9318671eb3ec3206d6cd2e38164b2c8d4a722630c029864a034261bd7efa9c048a8c7231da3cf2de4ca4f8c4ed33cb2742766f953547068416a1f294f553aceff7e468ecfedf4fcf6f6af1885eff4357
#TRUST-RSA-SHA256 b09387f4fad9032b89251afa3bf702e2cf781b36040fc3b33f6a209c9d59dea950ebe6ddac83a8e72562ab36dc84accfb536c56ea59c85a1a8c6355b80df484c0ef1d5572df1a652e6ad0a5f4dcf9ccf6e50b8b5f58b14eadc1749bf451b33be9453db771e3f5ac1fb8d603a19a3c2b76f539f9ef7505f01666a9af958a1c9ababe40cb08d2fe72422b3e11c30cd5689024dccc1297b01f56ff466e788aa15a2f666dc001726d187de1f75f13b9f8d06aba4e31b0eb71864b9bec9223dea1782cb7094ca6b1eb81ecd2c29bd18523754640ba994acd5ca6265d001aeda4321083de40a4351c477fd4c9c45bc559e9a9396dbe028aec8d46a07b5d37cef407d6b9857f2446eedac39fdce75a570cde7d46172551c525a9b9a9833d34a13dfcfd0b7c24026a7b105f6a0eb6270ddd23c2f9471e916751b768fd543cb97551dda4bedc250a0b5506950308945e40b49a4d99027fd199bf00c4c2553f7b5330dcea005ed9a886f79f5064c7b3d2757450eae57b40869203cdb8680760444a1304e350320545b5b1fe40c31ef28d2f9c317ec36b8d9e3fe63fb5a8416ca5ba70216cd375423c73c83941ff0754dc15947e1ee146d25eeeadb40ec40c9de640e01d9bfba668458a03e0507a5e93a9feaab7358353ff5b3dfd219ff5c428adfc6dd5d8b8a4a6f6cf9fd7d1fbd888a157a24532d3b6f3b21a07544a5ff13b6c32ebcdceb
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(123791);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2019-1741");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi77889");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190327-eta-dos");
  script_xref(name:"IAVA", value:"2019-A-0097-S");

  script_name(english:"Cisco IOS XE Software Encrypted Traffic Analytics Denial of Service Vulnerability");
  script_summary(english:"Checks the version of Cisco IOS XE Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is
affected by following vulnerability

  - A vulnerability in the Cisco Encrypted Traffic Analytics
    (ETA) feature of Cisco IOS XE Software could allow an
    unauthenticated, remote attacker to cause a denial of
    service (DoS) condition.The vulnerability is due to a
    logic error that exists when handling a malformed
    incoming packet, leading to access to an internal data
    structure after it has been freed. An attacker could
    exploit this vulnerability by sending crafted, malformed
    IP packets to an affected device. A successful exploit
    could allow the attacker to cause an affected device to
    reload, resulting in a DoS condition. (CVE-2019-1741)

Please see the included Cisco BIDs and Cisco Security Advisory for
more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190327-eta-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?23365f93");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-71135");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi77889");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvi77889");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1741");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/05");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list=make_list(
  '3.2.0JA',
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
  '16.6.1'
);

workarounds = make_list(CISCO_WORKAROUNDS['platform_software_et-analytics_interfaces']);
workaround_params = make_list();


reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvi77889',
  'cmds'     , make_list("show platform software et-analytics interfaces")
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
