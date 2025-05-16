#TRUSTED 36b98c5ae58f08673271e0c6676005cd95cc90021a43cc87bd2675ec5ae1e0727fb3dacf78235a8c7d431f2f7da6cd0c3bab12877265a5eb53ea56104a2ed36dba0efc61015ab43f5e20c603bb426c421ef5c780b1172be347727ae692604535b8ca978766373450c8367b7a9c1867052fa73d823899a4bcb0f479fe4129532752ab0e9d61bee0c3c02504fc09a23798fa4598d76aba9ab505b6d9e0ceee2ca82dfdd73522134a0ec994e21b4fc6b3d354bda99df9c4d58706a240edc8b7bfcbfed87872d7169de1a60388b9c5706d10f1641848922582dca0e8a68d00f73ce808e19f29872ca1b46f6490ac8d1135eff94b2932f99a03add477d4d6b4b2b0c74f1096460d22cc29a76678cdd7ca698ad359a16ec96302a3d4ff177075e1192740695de43b94dcc96e21462ae4a34d3741d5c8a528d16de4c8c56cc34f64aee0e12a9c1231bd8ac85a8d47935e9c52723fde940deba0358d52a3f8ddb4fb8b2d86007784484e4062cba33193a36dabc3a645abcd0c0502755e3425b0309207882973100d0503584dd7be22119c2e43598ae45b6f86a7c36fad659feb86acb052c95fc0c2eea75d47be3bc2ce4823b8b7f4e0d3eb066012ef95bccfccf290debf55983a095f59da6aceaf198408d7ca33ec6f238483e992255be43017b5df5c5ad041015cf9c72a616a7d42c0c9973b9d07b2ac167c8cf602696d9d7812c9e28b
#TRUST-RSA-SHA256 34b1170acc0db9af95139f2e7350ad17c84e48a8066ebec321fd94258399b2e858c9f3eb6f79944f34c00d8af736c4c1aeee53397da0e47072b87208ad2d0868cd8ebb6d7583af9c80a50d21d82a2ce8e1558c2a097993f277df95cbe2346eaa6cc006be80a3e700501f3aa2ee2a3c2f76622ffb6608bf1a1794fa251466f2050623169795e72b774a348b041dd92416dad7e1d7b842bba425b0cfc6fe599e98a98ac97d59fd7a1e095c903dcd24503643dbf46bcfcfcf47080581f8d14b5a4b9a8ecba0bfea6a895ec29c69e864ca140e94c006740777cd8890a6b85116f16a1c0d9a27c3fe11ad99a6c51e92b6d5afde709e8e99c8a1497c1dc1e90f5d9122d4ed16b091058fd59b040bcc49788d87519c5df069f14a2da0a8ba70f98139561709436ac0c76ab429824020902f92a5e56b06b0890b065f00ad456741fc46963089be5ab3108135102260825360474da8d6c5c9478e02d18b0bf150ecec7e461f73cb31565f8f3956ceeee67154788046a1d1fc0257ad8e4274df845156b87d5413ee8890f7f0412b16640ac27e5113c5447b648789ff2c9fd4a86cead21322acc349a046720dc0e828715f37434c8c11dddb69c255f17feabccff7ed5d9e3df8f703b8037de99ea19587868b7d0c6a73457bad6df1d197dc1162c776844f1b437e747eb3f46574b01dcc1db037bbc596f4a67cd653c7e380f889c7445859d1
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(160084);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/05");

  script_cve_id(
    "CVE-2022-20718",
    "CVE-2022-20719",
    "CVE-2022-20720",
    "CVE-2022-20721",
    "CVE-2022-20722",
    "CVE-2022-20723",
    "CVE-2022-20724",
    "CVE-2022-20725",
    "CVE-2022-20726",
    "CVE-2022-20727"
  );
  script_xref(name:"CISCO-BUG-ID", value:"CSCvx27640");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvy30903");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvy30957");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvy35913");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvy35914");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvy86583");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvy86598");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvy86602");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvy86603");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvy86604");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvy86608");
  script_xref(name:"CISCO-SA", value:"cisco-sa-iox-yuXQ6hFj");
  script_xref(name:"IAVA", value:"2022-A-0157-S");

  script_name(english:"Cisco IOS Software IOx Application Hosting Environment (cisco-sa-iox-yuXQ6hFj)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS is affected by multiple vulnerabilities:

 - Multiple parameter injection vulnerabilities in the Cisco IOx application hosting environment. Due to
   incomplete sanitization of parameters that are part of an application package, an authenticated, remote
   attacker can use a specially crafted application package to execute arbitrary code as root on the
   underlying host operating system. (CVE-2022-20718, CVE-2022-20719, CVE-2022-20723)

 - A path traversal vulnerability in the Cisco IOx application hosting environment. Due to a missing real
   path check, an authenticated remote attacker can create a symbolic link within a deployed application to
   read or execute arbitrary code as root on the underlying host operating system. (CVE-2022-20720)

 - A race condition in the Cisco IOx application hosting environment can allow an unauthenticated remote
   attacker to bypass authentication and impersonate another authenticated user session. (CVE-2022-20724)

 - A cross-site scripting vulnerability in the web-based Local Manager interface of the Cisco IOx application
   hosting environment can allow a remote attacker, authenticated with Local Manager credentials, to inject
   malicious code into the system settings tab. (CVE-2022-20725)

 - A denial of service vulnerability in the Cisco IOx application host environment of Cisco 809 and 829
   integrated service routers, Cisco CGR 1000 Compute Modules and Cisco IC3000 Industrial Compute
   Gateways. Due to insufficient error handling of socket operations, an unauthenticated, remote attacker
   can cause the IOx web sever to stop processing requests. (CVE-2022-20726)

 - A privilege escalation vulnerability in the Cisco IOx application hosting environment due to improper
   input validation. An authenticated, local attacker can modify application content while the application
   is loading to gain privileges equivalent to the root user. (CVE-2022-20727)

 - Multiple vulnerabilities in the Cisco IOx application hosting environment. Due to insufficient path
   validation, an authenticated, remote attacker can send a specially requested command to the Cisco IOx API
   to read the contents of any file on the host device filesystem. (CVE-2022-20721, CVE-2022-20722)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iox-yuXQ6hFj
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6323327a");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74561");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvx27640");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvy16608");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvy30903");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvy30957");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvy35913");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvy35914");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvy86583");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvy86598");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvy86602");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvy86603");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvy86604");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvy86608");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvx27640, CSCvy30903, CSCvy30957,
CSCvy35913, CSCvy35914, CSCvy86583, CSCvy86598, CSCvy86602, CSCvy86603, CSCvy86604, CSCvy86608");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20723");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(22, 77, 250);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/22");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version", "Host/Cisco/IOS/Model");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS');

var model = toupper(product_info.model);

# Vulnerable model list
if (model !~ "IS?R(.*[^0-9])?8[0-9]{2}(^[0-9]|$)" &&
    model !~ "CGR(.*[^0-9])?1[0-9]{3}([^0-9]|$)" &&
    model !~ "IC3[0-9]{3}(^[0-9]|$)" &&
    model !~ "IE-4[0-9]{3}(^[0-9]|$)" &&
    model !~ "IR510([^0-9]|$)")
    audit(AUDIT_DEVICE_NOT_VULN, model);

var version_list=make_list(
  '15.2(5)E1',
  '15.2(5)E2c',
  '15.2(6)E0a',
  '15.2(6)E1',
  '15.2(6)E2a',
  '15.2(7)E',
  '15.2(7)E0b',
  '15.2(7)E0s',
  '15.6(1)T1',
  '15.6(1)T2',
  '15.6(1)T3',
  '15.6(2)T',
  '15.6(2)T0a',
  '15.6(2)T1',
  '15.6(2)T2',
  '15.6(2)T3',
  '15.6(3)M',
  '15.6(3)M0a',
  '15.6(3)M1',
  '15.6(3)M1a',
  '15.6(3)M1b',
  '15.6(3)M2',
  '15.6(3)M2a',
  '15.6(3)M3',
  '15.6(3)M3a',
  '15.6(3)M4',
  '15.6(3)M5',
  '15.6(3)M6',
  '15.6(3)M6a',
  '15.6(3)M6b',
  '15.6(3)M7',
  '15.6(3)M8',
  '15.6(3)M9',
  '15.7(3)M',
  '15.7(3)M0a',
  '15.7(3)M1',
  '15.7(3)M2',
  '15.7(3)M3',
  '15.7(3)M4',
  '15.7(3)M4a',
  '15.7(3)M4b',
  '15.7(3)M5',
  '15.7(3)M6',
  '15.7(3)M7',
  '15.7(3)M8',
  '15.7(3)M9',
  '15.8(3)M',
  '15.8(3)M0a',
  '15.8(3)M0b',
  '15.8(3)M1',
  '15.8(3)M1a',
  '15.8(3)M2',
  '15.8(3)M2a',
  '15.8(3)M3',
  '15.8(3)M3a',
  '15.8(3)M3b',
  '15.8(3)M4',
  '15.8(3)M5',
  '15.8(3)M6',
  '15.8(3)M7',
  '15.9(3)M',
  '15.9(3)M0a',
  '15.9(3)M1',
  '15.9(3)M2',
  '15.9(3)M2a',
  '15.9(3)M3',
  '15.9(3)M3a',
  '15.9(3)M3b',
  '15.9(3)M4',
  '15.9(3)M4a'
);

var workarounds = make_list(
  CISCO_WORKAROUNDS['iox_enabled']
);

var reporting = make_array(
  'port'    , product_info['port'],
  'severity', SECURITY_HOLE,
  'version' , product_info['version'],
  'flags'   , {'xss':TRUE},
  'cmds'    , make_list('show running-config'),
  'bug_id'  , 'CSCvx27640, CSCvy30903, CSCvy30957, CSCvy35913, CSCvy35914, CSCvy86583, CSCvy86598, CSCvy86602, CSCvy86603, CSCvy86604, CSCvy86608'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  reporting:reporting,
  vuln_versions:version_list
);
