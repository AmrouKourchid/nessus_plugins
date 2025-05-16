#TRUSTED a2f6d864a5d28309f16c4b852377c87d89ffdfb1a1502f64075e17f1f878e0d19f7ea2b721d73eac8a77d9d45f031dcd08f5f7c57fea4f3fa99c0945e1b656a3206cdc199cedd55642d08337d75167d8855449123c2b774e8918f6a8f7c071e5c2bae56ac3d3a663ee97b263b49786a26f38329d5ed5fb25da66dbfa6d1b88449b13695bfbc5d62bacfd093ca79eee801f04c8712ab262b5b99dec850618f68e67b468e13c36327bf21a25bb1c994b7935b7e1947841b42f609b643ad020440f415299bf97f8314e22c7c8554d457b7faaac2921016e4d80a39918c14e00b97d66e4612765056dccd2e116ff8096b4bb6cc8ab862b4a7dd1d3eee297d9dba9bd71c38882bec7ac163210358cbba86ddc9308702670444ea6d5178645ab96c8f5e933e39ba4d7ecc9b736245989d23f2d40afa791f4b9883c81185dfefc619654a41e737b60ed849907031eaf814f66b87a25a1cc78d50a9da7757fcd503cf219a75f8a225cf456aed2943545b5d57b5e995d36939f6a9d48028c673f931b0d6ff88381801d59468441f5f42ad7fde2aa1dc3394301b4e812b9920c770f9717c305e77ce705caec42362c748bfe57063c3dafb8fa172f915d0da49e45c4188920c6da387b86972524da4556dde9d81a3f708978962b0429b4f84083e1671a63aa125b1d421a2794b99fd4ffceb2bc42ec05c3c77775a6e9e4c9db364c0c9948f7
#TRUST-RSA-SHA256 5903fa1017adc0c760b2d2fcf94610811029518997b1c602de23ddaeb02f132cf6a833bd487e86bc7afbaeb4a170c91ddd0a374b3a0fbc6c35f64fa36d56ece707e90e717ad6e4560dbd6b54397984f6b548bfaee2f40982aa17521ac0646557b863172e22b2f17540d893767b8bcb4ec12283e5aa3bcdb18b650d21d936f9f9a920209a860c730c5235732a1ceb7d85d8e2cbe1845a8cde8ac1bd27671c40120f8af6cbc434f4ba2a56aad4f1ddd0d809c86f4116bbbd1202bcea84aa0469b3cb388309fac5c4182ee21bf4a13a9d13dfbd5155674db0410b7bc7b8827e7ece994e9e5568dd3b7e030a15dc60fed7592bb9749a665d457d4308a00713e7aee08d2fd0891e8c9362d3463afa2a2ff8314b49f1bac22949cd96574c563dea61222d3ffb6aa538e070ff5765c3976ae2a5d187683a59fd2c72153d86ca6158d4dcf89c1fc23b381e466531a04c4c35b785edcc64337c096064e238c3895f98bd42e1c4db253a98f1fe5e1294436ebf4cd673b5df9a0e60b7d9e02502fc4b0102a2e56bc7e18847d83032afca8bb255e153b61797ca4e93ba142915ec15e606c96a40608cbd06b8f0b5705e4087cc22d2a72626a22b868b130b30a6f2f0621ab4acca9a8312d8f794fefd1e5b917fb1f89ea4563d9917bdea067757d58850ad8316618f1671d5198c4c15d44d1942b3a72803eeb7b2a2b4a6671b3e2e162b54d975
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153562);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/09/28");

  script_cve_id("CVE-2021-1612");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt63238");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sd-wan-GjR5pGOm");
  script_xref(name:"IAVA", value:"2021-A-0441-S");

  script_name(english:"Cisco IOS XE Software SD WAN Arbitrary File Overwrite (cisco-sa-sd-wan-GjR5pGOm)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS-XE Software is affected by a vulnerability.

  - A vulnerability in the Cisco IOS XE SD-WAN Software CLI could allow an authenticated, local attacker to
    overwrite arbitrary files on the local system. This vulnerability is due to improper access controls on
    files within the local file system. An attacker could exploit this vulnerability by placing a symbolic
    link in a specific location on the local file system. A successful exploit could allow the attacker to
    overwrite arbitrary files on an affected device. (CVE-2021-1612)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sd-wan-GjR5pGOm
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ea29dee5");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74581");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt63238");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvt63238");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1612");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(61);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/22");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/SDWAN/Version");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XE SD-WAN Software');

var version_list=make_list(
  '16.9.1',
  '16.9.2',
  '16.9.3',
  '16.9.4',
  '16.10.1',
  '16.10.2',
  '16.10.3',
  '16.10.3a',
  '16.10.3b',
  '16.10.4',
  '16.10.5',
  '16.10.6',
  '16.11.1',
  '16.11.1a',
  '16.11.1b',
  '16.11.1d',
  '16.11.1f',
  '16.11.1s',
  '16.12.1',
  '16.12.1a',
  '16.12.1b',
  '16.12.1b1',
  '16.12.1c',
  '16.12.1d',
  '16.12.1e',
  '16.12.2r',
  '16.12.3',
  '16.12.4',
  '16.12.4a',
  '16.12.5',
  '17.2.2a'
);

var sdwan = get_kb_item('Host/Cisco/SDWAN/Version');
var model_check = product_info['model'];

#Model checking for IOS XE SDWAN model only
if(model_check  !~ "^[aci]sr[14][0-9]{3}v?")
  audit(AUDIT_HOST_NOT, 'affected');

if(sdwan !~ "([0-9]\.)+")
  audit(AUDIT_HOST_NOT, 'affected');

var reporting = make_array(
  'port' , product_info['port'],
  'severity' , SECURITY_WARNING,
  'bug_id'   , 'CSCvt63238',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
