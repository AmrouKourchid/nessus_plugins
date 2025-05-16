#TRUSTED 965af5073621e861dc0d948d9a2d22e6b280c8f9d121be01586ffd28f670c7ba5472ec4811e9eec93c840df73fbef01eeb5cc98db4acc5aaf84c18922fb5f394bb497bef87aec0e3e3b3d8bedf4355cb9be24a08aef2d8fd2e283599f22981cbc5ba02a46308d16c2182d7d65686976626348e0d3ba70a8b0a406aa01caf7fab67e6745e68223a61c2da23329bded7d41a54f661c0abd2cebe7a0951abcfca5ba277cba548a22322a18abf02f77050716ada15a10d0e5cd35a38bc836cd071f2116f4f320b4e95420d7efaaa40a0677a0b58793d2f72954014f9938a68280c7a1fd9fb0e48d475673f432d39612628e072eecd5e418e9f8ef8f090d464e07cb407faea9e2d3ead42a56fbf99902251a591e65be05d05f422408dae27f7a4492bae3d1135b511a35e902695a41f32af15d8865f6defb156012ae09b5a3ce1c2d327279bf55caa3bd6d26957f698bf71a73e88e5108485361c5bf08f0da320e4efcf1078169f2c6e64eb54e5780518844c4c217528642dde7bb1f71ca52c1e39de9e01541855f0dcb4c1a33ec623f45af814182194036554d18dfd7e58fbe3c0b47d3a35b3eebf20d80269499115cb45a062afd89797cd9be24aa3448f56325bef2bb773eec57289e32c984dac2d6a5d2ca5af7adeca74d3cf630bcae8172821c84305ec1fdac5e6c49b2dcc2223d374ea6150ed5dba7ca8647a4fa90959eada6c
#TRUST-RSA-SHA256 029e78c87be5984cdfbc44b2820c8aef677beb809cc41f6c9a332023b2c43a25e2728e5d91155c46a2904fc8c367c8b620e1307064242f00826edaa2f6580a4d2c43d114ec7b7c93fe89174c997a1ada170c676b9f024073a2e520d152e2da9872ef758351d244ec2db96164cb7761f7e09fb8ce5b08b152a982b4182dc96edd628d6623eb9ed2e3c8195c4c5f2009f1311d860eb266942efa22855430be3d2808adc46a6e9d058bc215fb2bc229cfaf886d08ee9ccc04f5db1aff84f4acd56d311e139d1df4e9ebbb292769c87dbf184119b24d5ce886fdec653f11365942749da68b2bee403b06643dba53917b32dd706ef8129295e6af9a63cb6b7ad46e85860259f574cea290dde9fdd641cc996edb81408f8a03eff69d334b62f68b0e27d88915c26fca80e1b85f81b4ae25684a056dd0a0460606f8db3366dc541b2188ad8b82549046e037a1bff3d2c56b4f852ab3cd3c9c32c34f07c55d04e50fae8192264e5ef152c7d77c10bd9a265add567ba08e420bf5678ec0e00cf0030ab4a34b270a019ba8b7b8961cd6c088202317ceccf63177b9ea7758461a968b6723ca8b08b7a0f5462b3788f7fdf87731298fdb85b31f5731277b1aef5d929384c8d4882ebe710be1c0851ac49d1cd4abee4887c9bf6543f260d237412981519aaf0af47136a0a2a0abfcade80bdb744d999b724f8a69ca4ebf44c26e298db4c2b82b
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(180164);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/08");

  script_cve_id("CVE-2023-20209");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwf57215");
  script_xref(name:"CISCO-SA", value:"cisco-sa-expressway-injection-X475EbTQ");
  script_xref(name:"IAVA", value:"2023-A-0431-S");

  script_name(english:"Cisco Expressway Series / Cisco TelePresence VCS < 14.3.1 Command Injection (cisco-sa-expressway-injection-X475EbTQ)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The Cisco Expressway Series or Cisco TelePresence Video Communication Server (VCS) running on the remote host is
prior to 14.3.1. It is, therefore, affected by a command injection vulnerability as described in the
cisco-sa-expressway-injection-X475EbTQ advisory.

This vulnerability is due to insufficient validation of user-supplied input. An attacker could exploit this 
vulnerability by sending a crafted request to the web-based management interface of an affected device. 
A successful exploit could allow the attacker to establish a remote shell with root privileges. This exploit 
would require running a vulnerable release and to have the Automatic Certification Revocation Lists (CRL) 
updates feature enabled. The Automatic CRL update feature is disabled by default. However, an attacker with 
read-write privileges on the application could enable this feature to carry out the exploit.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-expressway-injection-X475EbTQ
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6e340f61");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwf57215");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwf57215");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20209");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/08/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/08/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/08/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:telepresence_video_communication_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:telepresence_video_communication_server_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_telepresence_video_communication_server_detect.nbin");
  script_require_keys("Cisco/TelePresence_VCS/Version");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco TelePresence VCS');

var vuln_ranges = [{ 'min_ver':'0.0', 'fix_ver' : '14.3.1' }];

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_HOLE,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCwf57215',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
