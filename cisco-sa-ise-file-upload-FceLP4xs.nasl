#TRUSTED 94e5a2ecf7d561aa8157143028d1ce83bdfd54dbbf75a86f0a9a51d40d7d81004313f809e1ee1b0320a22d1de334c0e2c10867009e99a581b19f768ea8f9d0bb77518f93c44a92ef6750224ed2dc9b31abc15c16dd4d90c0ef77cdcda2de09388ab74d36e9efdc131d2a57aa37be1746ea811e0b5d8b7465fceaf7c3d12e6ce24ce3e8b8a0db36cad8d88afe4da4cd89ce499a717f86e1eeaaeb1cc52aa8a495c7592e1f57f3980e07d2a6dcfd32274b000225ea8ef3baca86e013e80095e328e65809d0e2e3ef317832308d7de7472a9d20b470b15c3c735ffe23755c8d37fb33bf44be16f9542de29803284c0d659c9b0d6e6684c19ff8f00d62d0b7c21f4ae85bf0d19e83472ba8059b1fdcc63d5d038d2e2a94d12fbfdb2e744a8715ea246cc26115bec44a9d39525b7b77545fd0f03e4f176e5ee169470bf3de6e7963c1a926a87cb7eaf6c8d654d664d263536530072572b9a2307da0e12cb15e44a9e0611e07675c7507af2fe31dc3dfd2b3b42654989503be4c4334e9a09fcff005dbcc336e11863e43095cf438182d8fbc59d4f16b7e28b0cf4e34ad8c4d6b39a95e147bbdd365133da5958ba23cec0490defe6a621a0c9ca1a60fa3b2f1d497250c0823b62ca8d65515b4e079a510f4e8f6b92672ff84054fcc3c60c6e0abb4a1bfc53733f7efdcad83a27dc8d9839ba758f37439a2eed08df3ae9551d632e8deb9
#TRUST-RSA-SHA256 1fc50bae6bdee8bfcfa1f682a6a50802e9fdc47adadf9dd4e179d7f2d07656675d2d852d57263862f34fd6e0e89d2992212a6496ae685680687b2da48ba3ff18ac95d4ed18fb9c52bbeeeb4bc936dd2b4c9a0154b5c516d5172c05cd8f0d5e8060fb2829dc66dd7ecbc4f10b545d8441caf92855a55c2a0691b74ab2d15b03f2fa59ed894b30ab6376a9d916371c7bc747fd5963e82afece0f4037a487c7ecef77d3eafeddaa4bf19f8d8c6374dd90106817402491d89b58d2b2e4af27f16d71ac8a4e124e749a8ec4db0232bde14a3333b89dc350f9b043eafaa210ca71b1afbd7064b8b0a1404e3be4ab9b5488f282bd5c727c7e671b56e31f5c9d539f05c0c6f7be125508e7e79d60b159ccf9d8597504409d944593ba5ef5813b34140bacba315201d65909dc75c93b641840df1cc1813369271b104994dd029fed02db092e3fdb4dc878606d1d844b3da3941fc667c329c8c95f673ac5b5a40e0a5e378053a3fbd586a762b7f06cf1369e90839c77017498f266d91cbc4ba42c1f281a79fd7740216845c2a46a53b933c9c46474d8253898007422783c3dc5705d81cb0e6204f34a406a9b02f8a2143391ed9bd01060cedc0d017dcd3d00f43d242ec3e3977967b235336badabb542de261ea1b6a987edb9bb635416eb1a16a70f0e0fc9bfd02140c25fab9306d03b3f2cbfa0e15d5ab00f538173664a548531c6fdefd2
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(184454);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/10");

  script_cve_id("CVE-2023-20195", "CVE-2023-20196");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwd93717");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwd93720");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ise-file-upload-FceLP4xs");

  script_name(english:"Cisco Identity Services Engine Arbitrary File Upload Vulnerabilities (cisco-sa-ise-file-upload-FceLP4xs)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Identity Services Engine is affected by multiple arbitrary file upload
vulnerabilities. Two vulnerabilities in Cisco ISE could allow an authenticated, remote attacker to upload arbitrary
files to an affected device. To exploit these vulnerabilities, an attacker must have valid Administrator credentials on
the affected device. These vulnerabilities are due to improper validation of files that are uploaded to the web-based
management interface. An attacker could exploit these vulnerabilities by uploading a crafted file to an affected device.
A successful exploit could allow the attacker to store malicious files in specific directories on the device. The
attacker could later use those files to conduct additional attacks, including executing arbitrary code on the affected
device with root privileges.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-file-upload-FceLP4xs
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1997855f");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwd93717");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwd93720");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCwd93717, CSCwd93720");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20196");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/11/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/11/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine_software");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ise_detect.nbin");
  script_require_keys("Host/Cisco/ISE/version");

  exit(0);
}

include('ccf.inc');
include('cisco_ise_func.inc');

var product_info = cisco::get_product_info(name:'Cisco Identity Services Engine Software');

var vuln_ranges = [
  {'min_ver':'0.0', 'fix_ver':'2.7.0.356', required_patch:'10'},
  {'min_ver':'3.0', 'fix_ver':'3.0.0.458', required_patch:'8'},
  {'min_ver':'3.1', 'fix_ver':'3.1.0.518', required_patch:'8'},
  {'min_ver':'3.2', 'fix_ver':'3.2.0.542', required_patch:'3'}
];

var required_patch = get_required_patch(vuln_ranges:vuln_ranges, version:product_info['version']);

if (empty_or_null(required_patch))
  audit(AUDIT_HOST_NOT, 'affected');

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_HOLE,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCwd93717, CSCwd93720',
  'disable_caveat', TRUE,
  'fix'           , 'See vendor advisory'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  required_patch:required_patch
);

