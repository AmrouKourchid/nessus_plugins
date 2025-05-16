#TRUSTED 0b8de613802e1616abde2490f52a807779e062fd1dbddab297e39ed54b4475ea2640f4c7c4cd32fa3584ce38b0e519f9ee813c7f7a15ea5a7b357a6b33a19b02793fed7c9bf658e5967005e3fa40cd750badb78e56d7b88976bf466dbf50b171451185fbf1d58a43df4f8e0872dc643c5a2cc25b3ab0c55a288c4e87d499737009af0828389c960d3a191c327e9201486d973cc7f33451d1f51bf46b4b0eb1729fd20c00c1789d2ad1beb6a8c126dfe2c4a9444b4c78b70206e22851dcc27f62a5b3fd20a4b0529c54b6e71576c77364def9f2863dae289c3e8f93fb1dd2ce1cd80ab51d3f619df165eb9c11e46826940e901705568e163844b3171f770867154a9efd1e5583c784239ba4a2673ef64408e50422505526bb8db110a1b5b1b5b809520adb94262edd92b317e937b40750fe2494c455ef3bb5b833d52e5365e25a1fa2acbb2de2bd574d14a1b124e8ca2e37fb827f0efcaab759720859de944e87e9b3ca178cfa419626fb83d54507c8270c82cc799668d96c829d175b96964774e5215600696e037ce68d48a6a03660d00bf139ab560ced8c36fb9ec749545568651558fb1fd9f35ed23e7eefe3030edba47f015f4dafe02a00d7e6314cdd275312450e0042baf60e4e8ee0a206e3834e49230dd64bd2f75559d43eeabad12aada34291ec0bcc8d28bcbf75107dfcf4ea042fcced1686e49af46ef428ae892e9e
#TRUST-RSA-SHA256 42a7c45e0ca1ab6d87fa1fef271404e1ef9f21202cf002653dde7a313bd1537b9a4ea7de5c3842aa0a10e6674f0ab0b8979bd9add68451b8ae14429b411093dc0928b020843931bc65fcce8082a0f84f886732f2a2d3cee74de14eed86fcb76d17308e4892a0576627207b494320f07b60d5e1062f51fadf720f9a6d652495bef50e523bf2170f4328874f4079edf22670bf4483e06175a3059dd345d6c17605501de52102fce4a312f8f3e08cdc5808d8945a468014e28b25d6179b0665b4b71e93b80f2bb1499d0da9a482e5e5de0d7c8ab7ca766682da1cc36641cc853c6c7903505a992f64d6cc1dcedfba772c92bfbdb9586da7dab4b1fee697b8e03e3e0c3fc5a65a99375fdc7fafb678c7c817a81de5a1ad5cb3066cc40d04dd22e935070d42cb93fa0349d6958a4a09ba6aa9e45c63a18599ada65e7e861852480978fea1ad8bcba63a06540bd09fb944e69ee3abf67b03e047f83fc2bb345da8a7bcfec2605714b959d27654b619662ef2ac1ec6d4e1a8d19cd553cb8bf6bd2e090f0543e2a6d0574ca385ce6fa1389702b538e7176f192d5a8c00d9764d0cbae3e367b4bc07cf9e26f262985f79c5ad511c7eddb8404193bd2b403647e919ea1fa2cfb48990b74a9e400468ad06b9445c901aac2e3ae26d38f3354814ab1514ee67e4f27b9cf3f1084b925931dd6e5477e1691055f3c07222fa058b50c4287e06eb
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151661);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/09/21");

  script_cve_id("CVE-2021-1359");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv81569");
  script_xref(name:"CISCO-SA", value:"cisco-sa-scr-web-priv-esc-k3HCGJZ");
  script_xref(name:"IAVA", value:"2021-A-0305-S");

  script_name(english:"Cisco Web Security Appliance Privilege Escalation (cisco-sa-scr-web-priv-esc-k3HCGJZ)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Web Security Appliance is affected by a privilege escalation
vulnerability. A vulnerability in the configuration management of Cisco AsyncOS for Cisco Web Security Appliance (WSA)
could allow an authenticated, remote attacker to perform command injection and elevate privileges to root. This
vulnerability is due to insufficient validation of user-supplied XML input for the web interface. An attacker could
exploit this vulnerability by uploading crafted XML configuration files that contain scripting code to a vulnerable
device. A successful exploit could allow the attacker to execute arbitrary commands on the underlying operating system
and elevate privileges to root. An attacker would need a valid user account with the rights to upload configuration
files to exploit this vulnerability.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-scr-web-priv-esc-k3HCGJZ
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4eb0fcf3");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv81569");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvv81569");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1359");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(112);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/15");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:web_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:web_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:web_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:asyncos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_wsa_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Web Security Appliance/DisplayVersion", "Host/AsyncOS/Cisco Web Security Appliance/Version");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Web Security Appliance (WSA)');


var vuln_ranges = [
  { 'min_ver' : '0.0', 'fix_ver' : '11.9'},
  { 'min_ver' : '12.0', 'fix_ver' : '12.0.3.005'},
  { 'min_ver' : '12.5', 'fix_ver' : '12.5.2'}
];

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvv81569',
  'fix'      , 'See vendor advisory',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
); 
