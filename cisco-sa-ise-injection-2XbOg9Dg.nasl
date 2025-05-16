#TRUSTED acb3832e4ed7056251829aa359f2adb37cbf39d11e251499ec4be5e79c40fa21a84614c3012c166b9fd2033f4aca646819f15b0d688ae8dba89a98e2b88cee45bf86e58a5b0b35bc07dd36ee5cc928937ad76962e007669e063e369f767f684578324840a9c59bc83d73d2a86702cb9b1a696af3ed3918d86b3959cefd4858c136c8bac4f317864c21031349a08a5528d939b33a5e470c6113fa6704fcd2215c67df490665f388f5df94b40f12f2bd9ffed5c916c3420693bf6fa8d455f386641bd4e2ccefda4098da79484ffbff93c9aaf5cb42b4248fb2c370ec4fce5bb03f338008014eb735d5f79175b4507a2839374bd2e01271743f71d0d5d6901e6bc94e96661a6ae23b91b2a96561dd87a3dbd48aafd8789a3e3037550b5134aa63ca029a5313fd10a1f2ea7845754527b356111768b601068f1b1df7ce4a6661742fd913232faaa4ae19a34ec72197513efd52f66f457a857b02a657a7cd86ff2e41acfa82bf6d9514c58ee0bee4ad66a9526946e857b55410aef7a3bba317b02cb7839f2cff4cb91efd2f78840ed60e80eb320a69f3606044f82bf387f6ab0644436855673596780946f8d94fdc4145318ea6c04df53621ce4f9c42b2450ce93ab4b8c74fd07a46cdf096eb0441e8ad964dda75fd384a294dd7c0cb57afbe25808f22f79f2350b9a333e75f617b0f590003fdebdd8fd50487cfe3a4ba3cacbc62ca
#TRUST-RSA-SHA256 7c921c93967e1e233e81a9bc8e92e7c3a0a43bc761d869a995b62404260c65c07ff17d312d02345af6af5ebe2b7bfaca0eedca6d8a5ac64996b025cecbfb32197959b4eb002d1b97c6a3d7ccf2b1454b3675b0141b74222de998e7c08331a4fa2faef0b51572526d4f3fb217b8cf747b8a804764c2a01d919c301796cefb9bfd019b75cf74451baf6adbafe048c8764cdb37d003234d9c25b969e640ad13b83c0ee5d2dc66e8c188f1922732a880824143ca786a06606d745729f4ded25b02aa7f452fb2cfe0665da91a699a167f3dd06024bf0e4bab36ae55e5d07ab86493903b712382b0489b38e2707ec791a29e0ec856fe3631ecc75f7f519cbd386337ef8803be9cf3877f7e857a92cbdedd5cb4b16b92d93778d4930047669cb7adce68827408a01bec6c9720436abe4705860bd8a05069f5c13ffee919429736c14d0b9cd213ec3b86232a3ab0fb189a246120ff1f47d00febff6ff1610e4a63e71ec2a66993049fe3c8ac776ce2de029fd0c04efaa708c0ebe321256e7c6b07772d545f1d8de66f030e073b8370dec94b247136e6f73e19dbd5d18336d325be876b80a1e286cde75494611aa4cf9bd33bec55b65955e12717ba7100028d38355d983f3672d3c7951ccfefb756a7047c7fe05a0e33a3b7dbc6976d14f2b1cde51200941a23289d7a8f7c6bb9b056e23bb3f8eee3b845d45ddfac288cf9c5bea90aa341
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(173952);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/10/24");

  script_cve_id("CVE-2023-20152", "CVE-2023-20153");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwd07349");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwd30038");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ise-injection-2XbOg9Dg");
  script_xref(name:"IAVA", value:"2023-A-0065-S");

  script_name(english:"Cisco Identity Services Engine Command Injection Vulnerabilities (cisco-sa-ise-injection-2XbOg9Dg)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Identity Services Engine is affected by multiple command injection
vulnerabilities. Multiple vulnerabilities in specific Cisco Identity Services Engine (ISE) CLI commands could allow an
authenticated, local attacker to perform command injection attacks on the underlying operating system and elevate
privileges to root. To exploit these vulnerabilities, an attacker must have valid Administrator privileges on the
affected device. These vulnerabilities are due to insufficient validation of user-supplied input. An attacker could
exploit these vulnerabilities by submitting a crafted CLI command. A successful exploit could allow the attacker to
elevate privileges to root.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-injection-2XbOg9Dg
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?570a0f99");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwd07349");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwd30038");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCwd07349, CSCwd30038");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20153");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine_software");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2023 and is own  ed by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ise_detect.nbin");
  script_require_keys("Host/Cisco/ISE/version");

  exit(0);
}

include('ccf.inc');
include('cisco_ise_func.inc');

var product_info = cisco::get_product_info(name:'Cisco Identity Services Engine Software');

var vuln_ranges = [
  {'min_ver':'3.2', 'fix_ver':'3.2.0.542'}
];

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_WARNING,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCwd07349, CSCwd30038',
  'disable_caveat', TRUE,
  'fix'           , 'See vendor advisory'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  required_patch:'1'
);
