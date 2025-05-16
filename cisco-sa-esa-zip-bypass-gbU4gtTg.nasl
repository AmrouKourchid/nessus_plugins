#TRUSTED 0cb2fd204661f779a5e1512515352c62f96c3f9af01233ca6f13c279292075960e2b4b286dd1034d9d7b56104136acc5803b486a615b1c4c6eea8fd8f24f093c2326c847f5471e98654fe12ee48ca6dbc3b839584ddb8aaa17fa38c4414e4d305267ea14ce8c43ee1ce62ff05e9ea8fc1608945586aaead2f69c745e8c46d1561065e08d0b3c79277c917e5f1ccbc133ca07a3784d5947f49129fb061166ba9c86847b3fb9ad4265e561d7ecc746b49b019e2493fac5e365b997813a3d5b82e02d9fbcf17b15ae7d1929dabf046d25ea5a8cebf9182a21e446a776cf4619ffef4ff03c31e73167983dc60de5331e0361fbbced8f7efbfef4f8b04242947277457c04b1850a4ad7b46be53dfccc3d79eac00fa8dbaf5802ff37a6da7865f8a568ae4e5d972f3bd630e66579de4170da0c1318b8910d9464bd30e760c36a5cdf91833b69213f7281b620effb6ef460243e7e18e3f28ebc1dfd5e4dc9d6924d3146b0146be964b2e3de926957c2b7e5544ef113799cd38b3ddaeb990e078a902a532bfcee30366d175283555b16c33d70aa279b2054b54a94ffcf46c50b1b1f6694aaea6b5a4fa62a61a4decc42f2c82956522910466034fc60755ea76101c986e503c77eaf13e7443dd1b54b068bd7497e3be4750653e603548ff5c7da6f6703f5ebe39342b4fc76c16c7261b97fbb7144e19a91ff1b6adc0dc64d3f3b3d83afec
#TRUST-RSA-SHA256 a193bdcb9e536d5e1a2bbdaf787e9eaaad7a2165f5312c0b8b61b5b26b89189811932c1aac6659c9d0934e62e3b95863682e4caee58866c8c23e010075a9303deecc8146b9f4463bc5946a821e3f2d475d6a7a6c7f763f7467fd2942926e6ee05c0fcc5f63f105220a8366f3de458fdac138e15e97a7574cb1a4c32c3637509163b0fb3925c6a4ae8df34626a934c6387758ca41065d8c8917679123fe613435edd6ac1c8d5a17e6818729b1f29ce4819fdc98b762cac7e425821cf4dc4ae84d6a7bc05027ca706734fc17b84c44d88b417b532e857d9114e317b4bfd8bd5ac276f8cf56be74fc733105410c66bcc978a4d9b4c1129de76ef0ab73d8ecdf8412404af28f4dd66070b090f5be8e3db94e00960398821d94e690806ad681de8a93bd0f141906e80d61b8ace93c6d99caedeae428b1e395a9509c3c7e18b05d5541569ba864f34e705e5a17a3132454107268bfc67714053229d63200e4c6b69e96a5c227a3b4e6fb99fd29235f37feed970306ab7af40f69dcf750524106661923a80499617eabd45515688fd853864c708f4935faf0a3652b67b01b2cfb2e780f593cdc744393505e24f6054df6ba539f86e971600c15a0569a02fef3fbee62a89c335bbcaef45ea495df3341b5992f8c80c7a45a94e00063eb2c00982fdd0ea2115a25ed445eebe826e839222e17af1ce92619da905a5af5e46b2ff611733708
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149847);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/12/29");

  script_cve_id("CVE-2020-26082");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv38679");
  script_xref(name:"CISCO-SA", value:"cisco-sa-esa-zip-bypass-gbU4gtTg");
  script_xref(name:"IAVA", value:"2020-A-0447-S");

  script_name(english:"Cisco Email Security Appliance Zip Content Filter Bypass (cisco-sa-esa-zip-bypass-gbU4gtTg)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Email Security Appliance (ESA) is affected by a vulnerability in the zip
decompression engine due to improper handling of password-protected zip files. An unauthenticated, remote attacker can
exploit this with a crafted zip file to bypass content filters.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-esa-zip-bypass-gbU4gtTg
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ab126d2d");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv38679");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvv38679");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-26082");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/21");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:email_security_appliance");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_esa_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Email Security Appliance/Version");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Email Security Appliance (ESA)');

var vuln_ranges = [{ 'min_ver' : '0.0', 'fix_ver' : '13.5.2' }];

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvv38679',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
