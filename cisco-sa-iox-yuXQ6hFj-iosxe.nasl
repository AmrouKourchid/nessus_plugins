#TRUSTED 9ad665aaaadc5096de8163f429e6fd29e3dac758d15f777cd4c69129e53183a134126ec14069afa015fa18333b23b94d012e3914f368275783dae8939c5f1ec72cb792e5169f45622502c8bc09a866a55431ba06b3d1192b47166096905317ffa5b86a8b0cd7fc38a2ef5bf27b1d3c4a179e6ab9ba44fc77cb2884c3955e22ec3dea9e32ede9ac8abb41f788d9d6d60ea9b2abe5bd125aeb1b0d53a848c961614867dac953677131ca52055003119b7915769c688fe24fc0b64f4dabc7a391c09508a48801891554611f0c7081fe6d4314d7f79d3f1c057cc85b76c2fa66a2f8cf3e2d9823082ec35b770e7d803fe9451a7d94af869b247bc88b597fe279eee0471a74a68fa825470ab1e3dce235620bb81ad7b47e6e7bf86b05f2cec93576cb13338803eb116e8111095e44356906705f472d43c2da3a6553fd844657c7836b0c742d6cb86381822a0e7a978e0642e1478e0f019868cc840f11967b0f63a0bd26c1bbba6d4e656c3ed7cb829bafb8773efd957868b0e41b7a93d7a34057d679ffda84a269d671587747df42d28b69f335e059204d23c29e881e02207d21a402bdc5bacdf7a079b1ea11478a95db43d6198ae4c0a7542459c0153cc5c19cc949d35048fc4ae7481dccbdf3a8ef30137af7563514b0c2bbd1a0edb17843ec30fe29be3e3f91dca9248d3665c202279a88b06ae8fa9a73666d12804df9f1b4f66d
#TRUST-RSA-SHA256 19567286b45269049696cd3e2c2fdf2275bc92e8e61e42f0b52e0cac970d97a22cbc5eae5c775d920474238df12f4f04d0780e136ca0d383288e81180e2ef0169921b5ff14458ce4fc9b02a366222f529a72c93a5f0fbb4c40d9353e47752015daa6dc71a08fd94824221b3ee1b3a41fe1f1b47655d7ed71d6608577d4952b1a6c680af6d74966094bb5fc8f296580a1b109f6aa27c236758fdca52038b6dacc993954d03d05d6b64f2e6410edc5fb90f15a7d3fa4bdb39ff4d8f4a535ecb84124c79e2784e89dc5b46187fe14963b1188c1bbf4365a6064f63523a32b39420936ca774b1ef9ff9a377587fbe09723a1804891a4df460b6fbfade03d853e35896c4453fffc5334e6086949153fffb44f158c36ef1a0b07c2d74bca7ec0224c9f1a0873928cbd663ebf7e7023580bb03bb76fbf4da7a7439ef6362ff9530db8ba38705494978e040e0b5e644724531b167cb469a48f62cc834267d6a7dcb29bcff297174b80d69dd6d27c0f453c32efcde2f1c1c21449a808401927af19ece9e2ab82ac8b72446d096eacf1c009a2d8ccbb8e90bcec6ec95a0180cf546dd0e64b37d9ce454719cbc0be83e6f8e642295cad071c7055a5eed65092c7052a4475b079332ae02ab8edc3aebadbeab755d1ac18cdb68aa8d61c21678d460121745f42868056f7f8497f3f84e866c164316aada97757f61d241564c4457153b5e20fb9
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(160083);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/05");

  script_cve_id(
    "CVE-2022-20677",
    "CVE-2022-20718",
    "CVE-2022-20719",
    "CVE-2022-20720",
    "CVE-2022-20721",
    "CVE-2022-20722",
    "CVE-2022-20723",
    "CVE-2022-20724",
    "CVE-2022-20725",
    "CVE-2022-20727"
  );
  script_xref(name:"CISCO-BUG-ID", value:"CSCvy16608");
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

  script_name(english:"Cisco IOS XE Software IOx Application Hosting Environment (cisco-sa-iox-yuXQ6hFj)");

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

 - A privilege escalation vulnerability in the Cisco IOS XE Software which allows an authenticated, local
   attacker to elevate privileges from level 15 to root. (CVE-2022-20677)

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
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvy16608, CSCvy30903, CSCvy30957,
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/IOS-XE/Model");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

# No model check as all devices with IOS-XE considered potentially vulnerable

var version_list=make_list(
  '16.3.1',
  '16.3.1a',
  '16.3.2',
  '16.3.3',
  '16.3.4',
  '16.3.5',
  '16.3.5b',
  '16.3.6',
  '16.3.7',
  '16.3.8',
  '16.3.9',
  '16.3.10',
  '16.3.11',
  '16.4.1',
  '16.4.2',
  '16.4.3',
  '16.5.1',
  '16.5.1a',
  '16.5.1b',
  '16.5.2',
  '16.5.3',
  '16.6.1',
  '16.6.2',
  '16.6.3',
  '16.6.4',
  '16.6.4a',
  '16.6.4s',
  '16.6.5',
  '16.6.5a',
  '16.6.5b',
  '16.6.6',
  '16.6.7',
  '16.6.7a',
  '16.6.8',
  '16.6.9',
  '16.6.10',
  '16.7.1',
  '16.7.1a',
  '16.7.1b',
  '16.7.2',
  '16.7.3',
  '16.7.4',
  '16.8.1',
  '16.8.1a',
  '16.8.1b',
  '16.8.1c',
  '16.8.1d',
  '16.8.1e',
  '16.8.1s',
  '16.8.2',
  '16.8.3',
  '16.9.1',
  '16.9.1a',
  '16.9.1b',
  '16.9.1c',
  '16.9.1d',
  '16.9.1s',
  '16.9.2',
  '16.9.2a',
  '16.9.2s',
  '16.9.3',
  '16.9.3a',
  '16.9.3h',
  '16.9.3s',
  '16.9.4',
  '16.9.4c',
  '16.9.5',
  '16.9.5f',
  '16.9.6',
  '16.9.7',
  '16.9.8',
  '16.10.1',
  '16.10.1a',
  '16.10.1b',
  '16.10.1c',
  '16.10.1d',
  '16.10.1e',
  '16.10.1f',
  '16.10.1g',
  '16.10.1s',
  '16.10.2',
  '16.10.3',
  '16.11.1',
  '16.11.1a',
  '16.11.1b',
  '16.11.1c',
  '16.11.1s',
  '16.11.2',
  '16.12.1',
  '16.12.1a',
  '16.12.1c',
  '16.12.1s',
  '16.12.1t',
  '16.12.1w',
  '16.12.1x',
  '16.12.1y',
  '16.12.1z',
  '16.12.1z1',
  '16.12.1z2',
  '16.12.2',
  '16.12.2a',
  '16.12.2s',
  '16.12.2t',
  '16.12.3',
  '16.12.3a',
  '16.12.3s',
  '16.12.4',
  '16.12.4a',
  '16.12.5',
  '16.12.5a',
  '16.12.5b',
  '16.12.6',
  '16.12.6a',
  '17.1.1',
  '17.1.1a',
  '17.1.1s',
  '17.1.1t',
  '17.1.2',
  '17.1.3',
  '17.2.1',
  '17.2.1a',
  '17.2.1r',
  '17.2.1v',
  '17.2.2',
  '17.2.3',
  '17.3.1',
  '17.3.1a',
  '17.3.1w',
  '17.3.1x',
  '17.3.1z',
  '17.3.2',
  '17.3.2a',
  '17.3.3',
  '17.3.3a',
  '17.3.4',
  '17.3.4a',
  '17.3.4b',
  '17.3.4c',
  '17.4.1',
  '17.4.1a',
  '17.4.1b',
  '17.4.1c',
  '17.4.2',
  '17.4.2a',
  '17.5.1',
  '17.5.1a',
  '17.6.1',
  '17.6.1a',
  '17.6.1w'
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
  'bug_id'  , 'CSCvy16608, CSCvy30903, CSCvy30957, CSCvy35913, CSCvy35914, CSCvy86583, CSCvy86598, CSCvy86602, CSCvy86603, CSCvy86604, CSCvy86608'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  reporting:reporting,
  vuln_versions:version_list
);
