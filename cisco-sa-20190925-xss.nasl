#TRUSTED 19fc48b7fb5dfc16fd8922ca9e57c20c4f3c72e59f049300404d1bf01451be498df59fc6ae75b18af3b8f47fa4a3c45ae52542de7675c691fc351d647db1d25de8fc753b4eef3255446457b625ec6baeed2fd8ad6abb3d8ff21beecf47cc3f911e41c261638aa1eb331ec055ac695b8a71c4286884a3176fa4a0de82cece45faea45d9c7259d1e2a1d7d518e45c3e12ed5408858d0615048f3e53829486915155eb36a6d91b5d3833a47ae995409edefa22746420993706a503941bc13ff84564581a537420d1ddfeea679853b2fb65f3706956e84b7b2dd202a80cf0c43db5071e360a9b927c7bf871cc640346719ab30141c477f8453ba16273dbde3cef97fb892825175c1e9dda0df5189f9bee0039037ce007d5e617ad5c38768d30e658cb6b6c881956f2bb9a6a1e86fa586fe8926326d7880034939980668ca3677a1183fa7183a7b13dbac0ec5264b53e3061b0e44f8766b29915677286b2acdacfbb24fbb042a9007706f0702855962a609d9c46a0b2190c6445c925be6195eb741d327250f8f2b1894d1b437e6e4ac1b144cbe3d21c018fcdc6c23cc9461e22c497a1433c4322dc61a13faa379c0a910eb09c1e2264e4b5ce1e4999eff626e697e03f3db0a2753e3c637b0503f713993cd9f141f45ad8907bad77dcfd9417f4d4f5f78cfe1aa6627867fa33c6a2aca9b507c60378f5ce695921361e273d2d7668fb7
#TRUST-RSA-SHA256 0116c1ae54e8a8ca2f285e7170fe7145a00f44b2e9e49f3cb4edc4ebcf4d85cf1eb80cbda7656c15c96523f88899548b0916a6ee2a81a81adcbc99b64c97a21f6639db57f895c995e3ff37ec4964aabbcac1a5c7aa0f2f486b9de492d34efb60ab7b722c88ac1026fc282f91933dbd534440887f302a27dcafcb04a325579ac2c54c0392fd4d8c6652d45298ceaa2ddc1dde4bf07708ca923ac7a92f38c02c1ea7619b00ee569c63b04a567ad6976f27769b6c74c2624250b9dc58fe2bfc59a94cc0cc35f58966b40eee9d73a994d40032508e9c659fdef878ee2e3416b5bd58ccea6d4af2a9a9f38a16c61fcfc7bf5feb266c5cd76e10464d80f48061ee46d66314cfde9815cacb11ae550d40df9ab49871f32afed71f7d4ebd4afd01b37cbc23ad36f077624fc73c56df757050aaa9d523d2b42ff5416208d6d7ee0d8d97821d2f5cda7c52fd1c9096c27efeff43bb9857adecdcc3f173a79544b6104f709373f3cc918789a6f9b91833dee3e2f6c24a28c13f860eeab5b79e414f0b30d7c7ee94bedef9fb449329f3907d9633f5cf99c152fae790a85cc04ad0280d33072d50a0262fc7dbaf5fc68d7efd194219478a90c4bc89e13806edb69c22316c2fb32d138080717f70eb973ec3029aa0741fb720f5607c40f6e23e5672c001aacabc984f48db2caa33cb059e9c897deb6c380855c1efaaef74b39f470dc090cba7b3
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(129777);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2019-12667");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvk15284");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190925-xss");
  script_xref(name:"IAVA", value:"2019-A-0352-S");

  script_name(english:"Cisco IOS XE Software Stored XSS (cisco-sa-20190925-xss)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a stored cross-site scripting (XSS)
vulnerability in its web framework code. This allows an unauthenticated, remote attacker to conduct stored XSS attacks
against a user of the web interface of the affected software. The vulnerability is due to insufficient input validation
of some parameters that are passed to the web server of the affected software. An attacker can exploit this
vulnerability by convincing a user of the web interface to access a malicious link or by intercepting a user request for
the affected web interface and injecting malicious code into the request. A successful exploit allows the attacker to
execute arbitrary script code in the context of the affected web interface or allow the attacker to access sensitive
browser-based information.

Please see the included Cisco BID and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190925-xss
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e519691a");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvk15284");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvk15284");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12667");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/10");

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
  '16.9.1s',
  '16.9.1d',
  '16.9.1c',
  '16.9.1b',
  '16.9.1a',
  '16.9.1',
  '16.8.3',
  '16.8.2',
  '16.8.1s',
  '16.8.1e',
  '16.8.1d',
  '16.8.1c',
  '16.8.1b',
  '16.8.1a',
  '16.8.1',
  '16.7.4',
  '16.7.2',
  '16.7.1b',
  '16.7.1a',
  '16.7.1',
  '16.6.4s',
  '16.6.4a',
  '16.6.4',
  '16.6.3',
  '16.6.2',
  '16.6.1',
  '16.5.3',
  '16.5.2',
  '16.5.1b',
  '16.5.1a',
  '16.5.1',
  '16.4.3',
  '16.4.2',
  '16.4.1'
);

workarounds = make_list(CISCO_WORKAROUNDS['HTTP_Server_iosxe']);
workaround_params = {"no_active_sessions" : 1};

reporting = make_array(
'port'     , product_info['port'], 
'severity' , SECURITY_NOTE,
'version'  , product_info['version'],
'cmds'     , make_list('show running-config'),
'bug_id'   , 'CSCvk15284'
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
