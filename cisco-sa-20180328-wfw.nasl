#TRUSTED 11b74756561be9542598851b419cfd83b65330756716d08f95cfad6f12ecca9726139e9e3e20dad7b0427270c89ef43cd3264bb0f7dfc1ced19f32d0c3fca9906fc5d045bc42e7dce0cf804ac44dc8a102cb78bc97b985277daa21af0fc5ec3d37c7f719b576f90d4b9c6de07864936ac7066b881445cb9a641d4f6b09ec0e2740d15ba6d382b285efd6ecb1b6fe67214f2d3c07bb367e60f7faeee4026fc93e5764b8731e13fc8796e9397cbdfca2941879a6b3f5f62e836c3bd1f93c890b44d652b1e7f81e0f88eb0a4c37e845276cc6eb2635a2e5e1416dad4eababf327b43c022ad4d943d8ba682cb3567dc0e97b9209be72532ede42ea48bfdbce90da924765ce9e53987d4eef7a792e85b597a6c07f99eb0c01b25a93a63eb79d43d31dd626138fadc59df64b068e814ec57027262880b2bf00ad948d506e36c40e03c94ed0570cf8a521fb6968e2884f05114fc1eb747d51f3a245f1daed656a888cc7f651a8ac6c97494c14621d1abfe436b9b0d4ac776486fafc5fac489ef3488d48cfe361bf8150d59169edfa5d7abc1ba842c52b9e1710a60957dd177a3eaf035939d86df57c31d39de20796436ab1e9adc59494f7548a85ba16ee3657cbc88bd9c6f59cc5d08a4799c3a0da9b7ff7c1a3f30f7498dd9f8623cf5f3182d26858b4036dee0e48e448d870b6649ceee82ebe9c634318fa7330c8cc97b3cce1258a92
#TRUST-RSA-SHA256 3eeba0f1bc973bf4d5a856de72e794055824bdc2edf324097649c9a31c759b4bdf6d6a26f8500c80fe8d7f2d8b22bb70eb394a51596aabbbfb6cb6c4de66baf833eed3e748b7a75a6f08c09a3153dcfe604b659c267511806bb787c1dfb56291a11778530b1f9803fabe237d5d61dd7aa4f59e31d454adc6adfb04fa9fa9777d152d17440289e46b30a67613723422cc1ea232f1bcceecfaa3233e6f7d80b4be873e9fed6f425579c342856e5a09d0710e666ef607272f9e140ef7f04a1ae0d2f565d63586a00fb30567eb31dfabb05ad64c543ed383469cd06545f27eacfa1c986b2336d7e3b2f555cbbafb4f1556be6f8e29838a2e2c2f25f01a51bd5bd09922c8943741a5ff53a62eed5769ff5c8e4a98bc6e67650016377e770d899145a3ca28bdc90ba5615a45aa5600dc0ecef5fd373c057ed66c95e587f45a7be42327404e42b682d398716e7f09f026093955b93f7ab04b0ef39333b595ff9d63c46391b61b80be5e58305e6aa7fbf38c8f37ef8f82be4562304a47976bbde63821c9939a0dec3ecb74b44f5357b9e6711171676b5c02a48075f2487417d13b40f016e5ec759e5b33170bdd8b811461079fadf234b0ce0db6e9250503a909ba7829b7649f4ef0bf1e3a9d38a5621d73d70562a166fb2ec664d64ffc47461641fa5958f13bd8f405344980abb9de75254472570f56ce042f86668a7cde9cf7b31d4b19
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(132077);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2018-0196");
  script_bugtraq_id(103570);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvb22645");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180328-wfw");

  script_name(english:"Cisco IOS XE Software Arbitrary File Write (cisco-sa-20180328-wfw)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by an arbitrary file write vulnerability in
the web-based user interface (web UI) due to insufficient input validation of HTTP requests that are sent to the web
UI of the affected software. An authenticated, remote attacker can exploit this, by sending a malicious HTTP request to
the web UI of the affected software, in order to write arbitrary files to the operating system of an affected device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180328-wfw
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?84cc9812");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvb22645");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s) CSCvb22645.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0196");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/17");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Settings/ParanoidReport");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');
include('audit.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

vuln_ranges = [
  {'min_ver' : '16.3',  'fix_ver' : '16.3.2'}
];

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvb22645'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
