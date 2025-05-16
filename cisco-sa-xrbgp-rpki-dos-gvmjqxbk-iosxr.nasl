#TRUSTED 70ea1357f9f6ad7caa5fbb48c993732162a67f269a403b4ec658fa094ddcd3c9074e31082eb1ef9032b6e30a7a474d66e56742c72902b3f2c7bdba261f0251dc2ae522389e02e5c4832b045212589a6ac912809a78a70bcf8296fa0fc8dade0cbc016144a728c6a620ba223dccab4accb2ab4ebb1042bc9aebc130af37c94305a7f0a04a75037f1009df6553f7bb34676342a59ba8557dbcc49341a16400415d7f0e36775bd54343976de289258643c0a30f87e0ea164edb5cec19a8a789bd66631702c85766eb5777e8eaf82589f7bab613d8493fdd90933fcb838e6a58b71666a4dc7ae7eeb20de547786f4df1ca5f9ec0ba0d1df64979fa962332a53b62983d76489a1c68f42f00cda68bba9d42e8fc5ee35a3c05431fd7cd2d01e8f8d7c3527bf8b44678510d5f5d8dde0a865f1b1a8b6c41702ede1ef9f82257d4b2be688ef0ffe1bbc53ac33247f8312488af79e01c93a84415d9b3a12b2ac4838e98319eb58fde80ac9a84947f21ef6766f8be0b93acea7135629b72eff49524433853f47879f5e85305e84998e75df0062e5cdb49cb1759592471db93f2e6ac70b9656bc202a8f4db81d13d6b7f2df7dbf6012a38defb2a756284e0d45a866720481e520b3a51a3e3ceab6d1af2c27295cd600039432a912c08b3f035914ea0f889cec534c349819ade2dc65da123d7407bd4442f2a1b55c6e709e4a294c80e14e471
#TRUST-RSA-SHA256 ad4c8b6e7592f52b51089160457f11f25a86a9bda3ef261bfbb5c86010c242c960d39b796a3af1a15617146cb04fae362d2f9bb5148daebf6c443b7de12ea48cc1179a6a486d76c70bf3a60263652cbcfcdc9ab7e2df38285e70d47ab4f7c08dec8a7931bec7d83ccea1ece0cf872d4f323833d5d6e35e9373ed804019a2d1b495c8416a10d2ec029d2c6efbd7d2bd37e95709ab0817dffe509be36891d04d18d864d6f50a6b411a71193b18ec94b6f3f0ccb63d131ec8df32e7df7a574082259057cc9ef38b054c3d9c763ae352cc4373a1fbded2da854f79f1bdffaaae6edaa8a208f046884ff3e5b5e8068e6420ee4c43994a0740c1157389ffbd34d560e080d248633232bfbf7d296ec9d53a868c1a3a0b2087329b28893e890605ce5ebecde8d7ea3db7d250ff695d994c16028791d0be028864a7374103ba6115098ed3269943d5c0703e12b597c571c9c72e6f0b6774b31b80ec330b9e5416c7e76ad81efcd82effa3444eb3431e63f1c7996bdb1a7798148dfed543bf06c14e14d361ad4321be32144fe1c51bd65c0f10e2f9df6a3afc7243193a72b78e2ac76d45d83ba53380d1a43975a3a963bf1c6c2ef0804affd21ee2fdcff390e2c6a91d679566760bfc9fa8947b27be8a472468870f2860ac05a96187acf67ab12980c98efa0970f79f10eca5bd18d8062628ad33a492983006cb82578215caaf8dc5170a74
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153219);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/19");

  script_cve_id("CVE-2021-1440");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvx04451");
  script_xref(name:"CISCO-SA", value:"cisco-sa-xrbgp-rpki-dos-gvmjqxbk");
  script_xref(name:"IAVA", value:"2021-A-0407-S");

  script_name(english:"Cisco IOS XR Software Border Gateway Protocol Resource Public Key Infrastructure DoS (cisco-sa-xrbgp-rpki-dos-gvmjqxbk)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XR is affected by a denial of service (DoS) vulnerability in the
implementation of the Resource Public Key Infrastructure (RPKI) feature due to incorrect handling of a specific RPKI to
Router (RTR) Protocol packet. An unauthenticated, remote attacker can exploit this, by sending a crafted RTR packet, in
order to cause a DoS condition.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-xrbgp-rpki-dos-gvmjqxbk
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fd29f3b9");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74637");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvx04451");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvx04451");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1440");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(617);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/13");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl", "cisco_enum_smu.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XR');

var model = toupper(product_info['model']);
if (empty_or_null(model))
  model = toupper(get_kb_item('CISCO/model'));

var smus = make_array();

if ('ASR' >< model && model =~ "(9K|9[0-9]{3})")
{
    smus['6.5.3'] = 'CSCvx04451';
    smus['7.0.2'] = 'CSCvx04451';
    smus['7.1.2'] = 'CSCvx04451';
}

if ('CRS' >< model)
{
    smus['6.7.4'] = 'CSCvx04451';
}

# 8000 series fix is 7.3.15, which is immediately after 7.3.1 - so add 7.3.1 to flag in this case
var vuln_versions;
if ('8K' >< model || model =~ "8[0-9]{3}")
  vuln_versions = make_list('7.3.1');

var vuln_ranges = [
 {'min_ver': '4.3.0', 'fix_ver': '7.3.1'},
 {'min_ver': '7.4', 'fix_ver': '7.4.1'}
];

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = [
  WORKAROUND_CONFIG['rpki'],
  WORKAROUND_CONFIG['rpki_configured'],
  {'require_all_generic_workarounds': TRUE}
];

var reporting = make_array(
  'port' , product_info['port'],
  'severity' , SECURITY_WARNING,
  'bug_id'   , 'CSCvx04451',
  'version'  , product_info['version'],
  'cmds'     , make_list('show running-config router bgp', 'show bgp rpki server summary'),
  'fix'      , 'See vendor advisory'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:vuln_versions,
  vuln_ranges:vuln_ranges,
  smus:smus
);
