#TRUSTED 38cfcefa79367ecf3d50d113f29b13451f97aa0b3ccc5eae318a410b6362ddaa5a1678144e1fc6775ec6ae14f5d17e282137505c52a3f80c4b19a0d72c523fd089979877a28b2a717d43487ab2c8fa161bdd1733da6236e1c84457dc94f4344d37c7d72a08a199f5ceaf892dec21d9b16fc40d941677551fbcd80e166ba8765a990f304b52cadec7325d7a283744838af0078d982dabdcce822bbcf754f8a75f210090387e028121e893f0107be7e0e6c3a1359c2dd936ab846272026131cfcf6fae7bebc1dfbd161b4ba2afce032813c9320f68b053df3d4d574f688bdfd2bf1601b1f395ead7d362c44d215bcaa75a161ccbe042e61629c2ac61ed7362d8c24a7114bea2d4bdc3d96ab6ce6d61a2ab919fd9d1166f1b8d90c997b72bf41ab912ede0534e0bb60d872c8674d4196e1d6a702bf42008f69b90e7116e2ffedb5ee5e4ea4f4ea42f6f01330717903c058b5e7061adf74b1eedf30e4e4eec8bed42443503c025daab9a92d3a8c36c3b2ebdbb6332d8d32e70e27336fcdee6d93652bd588f98cc40777cdec74a8035b871a3af14c60db4cc0a51e021379bb970c09ee8d68f98a63c6b0441a3fd67de1fa67d0f382c10620c8102f99a81c6e48e840cf77086a918b494df426767eb4a5f6301809ebccf79512b559dff4160227b49fa191d8ea69dda562371945b4c2c59b054acb36de930b1709d2d4d5f3108a18104
#TRUST-RSA-SHA256 2629826c47face780f12a2fd61514395ac25e4ff8982e0ffc156d4099a13a24d598b408acaaa066daf3feb47ebd2cf6ab5fbe1b2b619cfd0a3556caf0aea6c8f85d3f35f16f048179ecff35b284cb0c493fe6e0ba1b59cbdbfbd6d08f8cbe80d36c28e90618626467e148aaa1a62b8b4d2c6b9c2c061d1894447de813fa2fc2192312b5887b2ae30a53641928c0ffe244e199bb2aa4760fa834c37fcd1c7ca4af920b4482f33207bd69a24f6eef9e1aec3372ef0e14357e596edfd1dc2dabc2fbd13fe36601e02a42983303fd0f0ef5adb867d0b3b41b7596e776bdad9e3c28bd24e16d8c9bff84cd4e55392f238112a99394eec715ebde69c842e825bc8be062842e0477b410a9d5fdbd74b74e5fe3a35f9f903762d799d93626fc5c24d3a83336d23b870863a41d7dbe6dcbd682ebf4bbdf2d5864f176d064758468c2ba46295bec34813c07b6ffa09391a4f9fa8709205b5f2ff92cacb6e1acc298aa3e77f0b378e08aa1b4da87e7a58802561ff12edba59324e53c29f86f074a8295b47c921c150eaddb35d6c2899dc39a9e4734b0318e31bea1c8d0d51085a71ff9fe3d8f9626155bdef074f77bbc3633f683064ec3d7fdae2258778c2bb472206e78a22c8393c946329800dd2f83f859723776f76098621a8900ef3081ee6cdaed62f7c3617a6fa8e536b8d687983dd3c02371869324bfd86274f1efc4ea77e413544e3
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(129586);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2019-12671");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvp34481");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190925-iosxe-ctbypass");
  script_xref(name:"IAVA", value:"2019-A-0352-S");

  script_name(english:"Cisco IOS XE Software Consent Token Bypass Vulnerability (cisco-sa-20190925-iosxe-ctbypass)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a vulnerability it the CLI. The source of
the vulnerability is insufficient enforcement of the consent token in authorizing shell access. By authenticating to
the CLI and requesting shell access, an attacker could use this vulnerability to run commands on the underlying OS.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190925-iosxe-ctbypass
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?10434195");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvp34481");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvp34481");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12671");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(285);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/04");

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
  '3.6.10E',
  '3.4.6SG',
  '3.4.5SG',
  '3.2.9SG',
  '3.2.0JA',
  '3.18.3bSP',
  '3.14.0S',
  '3.13.9S',
  '3.13.1S',
  '16.9.3s',
  '16.11.1a',
  '16.11.1'
);

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();


reporting = make_array(
'port'     , product_info['port'], 
'severity' , SECURITY_HOLE,
'version'  , product_info['version'],
'bug_id'   , 'CSCvp34481'
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
