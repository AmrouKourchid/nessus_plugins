#TRUSTED 6de7f72775c32396a4649ba3836297941694a6c51b5c65c5c565dacf4b0bfeff02fe9e0311f3dc43e2ddee2a539f01f06336e59f7057b4fc7943b2c9be90033be7a8ed0f3d3eb4ca6a899f0d4df69ba094974ed219567cd88ed18e42adb2de9302b144a7cb67e3d196adfaddcfa7d8580d8a030eb61c7de5c287c35ba6f7c51ff5ce280464f792a732e9c7e13c33a2962f0482dbf1faf4441b6f18874f7273adf7ad73ee3d29348d0f5e2c15e30349a4c1c973ca141852a4509fd070f64a483334cdab988e9ffe1bbc45cadbc85c3880b402ce1a51d8425983a1b74204fc1ca6532522bef4ab032a40293329179c48cf2aee207730ac5cb3fa06865b0c6babb874c2faba0a2fec200c0b15ef16d3a4c1dd41ba0c7e8f43f79b0e2273e0803e81cd03a3da8ad209b4df97d9dfca9a9f22e0cabd71b1f7e169e8df42da7a89f8a86daac00288c09e77b1f1a4ac6589315adbece2b5ba6fbed31ec379ee2ae0ad5f46eaa2a6bb797e49a792d4b01efefb0813df081f018b3f6cfc3408473ec19aa20b80eb2da8339e16517a9cfef019aa8f4aa8e3b624be66f92903d0c07bd3036e1102bd0526dd4e76c21f9cd2b6237789552fa7937834bbf4e332e24b340f6fcb7aba1ea51d6f92f826522f5f95882e3729ebed17825e8bc7c9a19ccb56988c5407da45821207b1b6e460ea2ab40bf64b847117ec6080c16310a6636d172cd9f7
#TRUST-RSA-SHA256 393c43bf09a0dcac1ffe4ce146cc3e4cdae23573c76b72aab3038e403c78465c9c2a0cf401a74efb040b630d42af29355380a37f72d35848894327b4c92a347ebe3adda26ede09335bf48701cc7f79a783616c45bded96b4c8d02c9faed477191f50056309926d7a71baac4669c2e33dab2a2c1513b267c484c52bec9f4401810705a4f9c33b0fb934436bb92b06294a16c9f65df2be252eaff16b48f4da9d50b3ef5c5259bca0af8ba7540a9df31dc7da2b2a3c8e81668ad1464c3513297d2ff6b3d78d468b4ce353560fb9f587b41fec939cfcb50461a50f281d8feaaa3e9245c8cab038c6bda5fab0f751aacc7b520116aac469edac9bd8d5c16d34af096e25b94adf8daf3e5da8960018cebd8b8e0da03ae8fc6a519108ba421aff65b70f19438cae830571cacc3ef88678024c48d86a8637658ae2bcfc62c26ab4d0c0969d8f102b026fedf730bb1cc7201b87709ffaf63736587247179bded9981a2d27f30515347543774b4b86f771e75bef7472c3d75adcd134f3c1323aaace1d41dea4c76ae267bfb299ad1ee1e57871ada08e686c07db3af4aea55a536c308deaa18d4984b9756c5bb8c90095f9ff8c83e5466d311f6b6f7be7c0250eebccf89f7261b007c33b2996d8bc1a96cb2dd11adfe086284112276c305c6856761eba5fbda75125844c3a5c2b068e5e083e4fce2983ccac7874bab123cf4063d758a9b5ea
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(165241);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/15");

  script_cve_id("CVE-2022-20846");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwb23263");
  script_xref(name:"CISCO-SA", value:"cisco-sa-xr-cdp-wnALzvT2");
  script_xref(name:"IAVA", value:"2022-A-0380-S");

  script_name(english:"Cisco IOS XR Software Discovery Protocol DoS (cisco-sa-xr-cdp-wnALzvT2)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A vulnerability Cisco IOS XR can allow an unauthenticated, network-adjacent attacker to cause a denial of
service (DoS) condition on an affected device. If the Cisco Discovery Protocol (CDP) is in use, an attacker can cause
a heap buffer overflow resulting in a restart of the CDP process.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-xr-cdp-wnALzvT2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6fe1a143");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74840");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwb23263");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwb23263");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20846");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(120);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/19");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XR');

var vuln_ranges = [
  {'min_ver': '5.2.2', 'fix_ver': '7.5.2'},
  {'min_ver': '7.6.0', 'fix_ver': '7.6.2'},
  {'min_ver': '7.7.0', 'fix_ver': '7.7.1'}
];

var workarounds = make_list(CISCO_WORKAROUNDS['cdp']);

var reporting = make_array(
  'port'    , product_info['port'],
  'severity', SECURITY_NOTE,
  'version' , product_info['version'],
  'bug_id'  , 'CSCwb23263',
  'cmds'    , make_list('show running-config all')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
