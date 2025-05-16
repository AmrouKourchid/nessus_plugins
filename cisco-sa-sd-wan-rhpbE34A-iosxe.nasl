#TRUSTED 512d6506dae6fe52b7dece665df887b78693a1b99faf4c68e1d154c73f7658084deb1fe0cdc6463829ee8c2cb243c9e4158ee3b4da6f5f2452efecfd45a681ced00c9522ae0c4eb3e920129fc9b32c4d956e065e44740ab601d83d93874a163733cf2f9de4a39bf8b7d2c30dacb812a6ab3913542e0b1726e5ef4c3f6d08cc2e4ee43b67cf8f9023ec4c2229da39340e6318e4b12e83c82581beaa19f8dd85d1b2e3d90b4e0f49b2fbd98ee05fc8d5b33a256c2b28ebc76f9b828c733cd83e6007236da5a9f6ccb78a54f0b8ad7dedbda86b5dcbb9a4996ae67b8edc12ba99ce8d5c2f935b52b71c6c19c17898321e2934c06e387f8b1681e3392b3ced3148fae07bb9eaf27f5fbabb0e8f7cb8d474fdcf662918b2c941eb45a1ae239d23b0fae4acd3336de0ab478e6f8dcc108458227de565034bffbbfcf117c0058382582d2d9972c8639a02504d48e68ceb612770f0a7e67d38a969c51eb2e69e67b2134a4aec26ecd8678c877dc4cd501d261c69f1bd064ac401f08248e4190fd24ff0bb3ff6d2494a3a318e4e5dc3f008879659691c4c39945b41b49499a467630d6159303a4dff46aa5527c90a5ddec1a9e3eea3669882a18330f8b9bf9d4cf444fc6f52af945ded7024b255f3efea66d8de65a9a9e6f24f921a633f511a68fa9e69e2b70c45eb03e834514d636067ed1c8a994a9878e3a6ee87751a8eee103b593824
#TRUST-RSA-SHA256 600c46790927423262cdaa39a1bb3ce448bc660d6623c168bcbad9bee9caf63dbf354f9a0f16a01a8fcc731df659987d5c7708bba20aae86800cae3c3a5d6d7c139c43f9af7c71151f8c43faed2593a5b1a9eb3ba91d7929263e69f1179815706a74f38aa134ce565be5eed110c468d40e9eb553ab6a4e659b972258255027643d09b15c9f8c4f21e7f844cb64d1c5db355b32d74c3bf28c22dd48983e368b33c9ac6c99df6d36eba8949996709e7cdebaef2b93b5591c625d9ae095dec91f778478c092a078b8d298029cb768b17dc859fa55d503e683e761107ad7a4f8e7a05204a61b18cca0201bb3d0c01a77217f6324cb97316eefd05f9c38b825940ff3c12053cbf65a6355e22bb2a2849496ad2df6fb9d543cdbdc2106d058b8ad6b0a3cc66ba2069039d6e6e8049b831c7bff4ebd5390e729afb971493446b38a0e67dbde1c987aa4f996ee111544d566849492f9cc5f9ff05e07bcc34a4572020c30847822218bfadc42e11cbee95e2aed886e4f05c3a536b30978769d583a4b77110b7188fe7621690868bb5eb62dd27239ddc965625a9eff03957606ec6c1ac6ebf98e66c6ba25da47d76f0de46a1f51a5eadb8e8770d9e8e5dd6ca2a1f5ab11331222d9da5d45bfed655248a60f9b5a58da89456d99b12a8d9166aa717c420e3c9bc66feafc96d8319ee1f4690efa9e4ddd5d5c85d417f2d64b8226634ab7a901
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154348);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/09/28");

  script_cve_id("CVE-2021-1529");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvx50713");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sd-wan-rhpbE34A");
  script_xref(name:"IAVA", value:"2021-A-0495-S");

  script_name(english:"Cisco IOS XE Software SD WAN Command Injection (cisco-sa-sd-wan-rhpbE34A)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A command injection vulnerability exists in the CLI of Cisco IOS XE SD-WAN Software due to insufficient input validation
by the system CLI. An authenticated, local attacker can exploit this, by submitting crafted input to the system CLI, to
execute arbitrary commands with root privileges.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sd-wan-rhpbE34A
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2e79ed52");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvx50713");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvx50713");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1529");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(78);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/22");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/IOS-XE/Model", "Host/Cisco/SDWAN");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

get_kb_item_or_exit('Host/Cisco/SDWAN');
var product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

# Affects Cisco ISR1000, ISR4000, ASR1000, CSR1000V and Catalyst 8000 series
var model = toupper(product_info['model']);

if (('ISR' >!< model || model !~ "[14][0-9]{3}") &&
    ('ASR' >!< model || model !~ "1[0-9]{3}") &&
    ('CATALYST' >!< model || model !~ "8[0-9]{3}") &&
    ('CSR' >!< model || model !~ "1[0-9]{3}"))
    audit(AUDIT_DEVICE_NOT_VULN, model);

# Vulnerable model list

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
  '16.12.5'
);

var reporting = make_array(
  'port' , product_info['port'],
  'severity' , SECURITY_WARNING,
  'bug_id'   , 'CSCvx50713',
  'version'  , product_info['version']
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
