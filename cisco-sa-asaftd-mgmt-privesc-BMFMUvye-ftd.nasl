#TRUSTED 15bd83fdde9bb27e6c5cfa1c1a49014740139a336cc8f02def13be41de8a7d269945695d7b1af153ddbfef5c5bfbc5959024125d2361df08f80f6181a891397b0d66ce010976a8cfa68d4cb36fd0afcdfcfa51ab24393c3f2eddc47a0bd7de71d5e4e9ec5b4bae28dfd9efc5a7a8cf72cb7c5b2b008592598ea7b9ceaa5c952e69ab9ae68ec25a936ad7279a20e39dbc16d146389ae55da13784e7e90eaaeb5c117d729c279eb6fb35ca98276b14fea0e5fc1a032352483a2503a7ec4f0c2fb7af93b91ab04828c5b2ab72ca304d5f3d7369ec326fef95c31cced39d9da3997721090cd8ffa87aa93e938cad182966f29b757d5341a1e03887d16a9d43577a03c211965fd6d3406b247e4baef2c0400954e81a895ad6639bfa4e152001b7d7b8e7b0730447f0a2cf46357bfc1f382c9111f5cad8e5892b1c0c49d2bec83893272f62c2505c7b5214e01bae2fc9ada639fd7124e278d18c3a94184fdd8bd90f3e23ac358f9c4ad8d8ce83731f5a8e2ba4282372ee1385b748adb2075fdfb039df5e7cab9f10b2cce6bf9bc9717985bd872a1f11e2d795a22331858e58834c6d7ac4ed29766106cc6e708f979392c44490fc23e2824c03e459e09d0c2118dbd3e79d7395686d3974256025879605b2966628cc93e7e80ac4794d36370f5fa64403bd7f95739182aef8ebc32cbc41108e65b6f3b9ead6433f4435836d12f35f9e1b
#TRUST-RSA-SHA256 14640f6100b4d33fee1820ee8c3be4e90314b804eb93d34db3dbb3736dd5267eb6732438c0ce1686f4328db4f1205a089cf50aaf63c28174621d1c33f82222af7b674ccd047245bee4bf47cc1149feb1d5ab2fe3d926b6ae81a07b33d4c0da8e91be6ce2bacc3564fc0fddea28588418b9bb44c8a28c868642506e368daebace3da7e4cacbf61a61578b1d7f936f2409754cf49f0891caff1bf81eee78a22f77b0a6d5a7e7c5bfbeb32030325f4c162363d8a4a553dadb0d75fdd6b0c3c9d57685157a4892fe017bede1a8eff572c72ad2409870b0e711a0bb1ec2c9f1f733851676bb0a3aad07ab772fedb4eec05e872f3add2c2962e53b9accd98cc547f848c24670cb1b381b95cfd441858c69a607afc322bfe339585c1eff7dbfedcfec505ea3c5603e4a32233f82e67a17f666b12582aec1ba3e8efff453b66aa7e9c0205cbf639ad02591830b43f65c1dbf41ae6f1da698904b15b73271de39a1e03f31a2e34507dbe39c4edaf6fdc02174c31e22cb56d5e6f911094271d1cf522fcf4bc75b7ee5dfb6f5240af980eaf2123eb084e6aac35a460bdf00c95c7aaa5757af7508f1b4a0c953c6e3c5cf8e25e7ae745ad106d997137f7f5d9f0b773054fca3fb49bdb06079e900b4a3c1ddc7a581f15b0639ab026c3750233fbade58725084e1f06516f609e6205c199534375c4f6361f598b3532f88a981464327449f09b4
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161182);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/10/27");

  script_cve_id("CVE-2022-20759");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvz92016");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asaftd-mgmt-privesc-BMFMUvye");
  script_xref(name:"IAVA", value:"2022-A-0185-S");

  script_name(english:"Cisco Firepower Threat Defense Software Web Services Interface Privilege Escalation (cisco-sa-asaftd-mgmt-privesc-BMFMUvye)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the web services interface for remote access VPN features of Cisco Firepower Threat Defense 
(FTD) Software could allow an authenticated, but unprivileged, remote attacker to elevate privileges to level 15.

This vulnerability is due to improper separation of authentication and authorization scopes. An attacker could exploit
 this vulnerability by sending crafted HTTPS messages to the web services interface of an affected device. 

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported 
version number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-mgmt-privesc-BMFMUvye
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1f748ef1");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74836");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvz92016");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvz92016");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20759");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(266);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');

var vuln_ranges = [
  {'min_ver': '0.0', 'fix_ver': '6.4.0.15'},
  {'min_ver': '6.5.0', 'fix_ver': '6.6.5.2'},
  {'min_ver': '7.0.0', 'fix_ver': '7.0.2'},
  {'min_ver': '7.1.0', 'fix_ver': '7.1.0.1'}
];

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = [
  WORKAROUND_CONFIG['ASA_HTTP_and_anyconnect'],
  WORKAROUND_CONFIG['ASA_HTTP_and_webvpn']
];

var reporting = make_array(
  'port'    , 0,
  'severity', SECURITY_HOLE,
  'version' , product_info['version'],
  'bug_id'  , 'CSCvz92016'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
