#TRUSTED 04bff18c557dc6ce7a80022b38bc8e29dc95312073f2c0a4f6e31e920fd2cec7126f9cdccfc626cf371fb396377d32623709557e80ef65c813addff34293f9b40d8a9d01ad6aaa0cb711d5649ee7f1c29e30501703d4474c30200d2e85523b7b81887d64aad8ed1657ca3b5cd99c836a07ee81067fe3a94902932262f98f5de7c585b84bdac0df702b0e63ef7e815e533b06cacddcce625d434a77781717fbc75cf42f021c6aec2d339674a96ca74c9cf4dbf311999ae8a25cb6d96e7cfb54153ac496e4dc3ee7c7b197031d0fa64f6a4f41846afcd4a7f90f60c8a90f7533cfdb07f6d960609dcb58d3d2beaec949b4f39765d23b885d0cee2ac48efda8a12c0860c735061894c827de47a4c1aa3b6404581cb953346615641c983d0264a592a63f65414ab378123ee3ded1954c1909a416dcd695656fd80bcfb0543356ac65adaaafe27457a7f4bbebf76e71bb74d4543d11ea0e7644fcea1a0e27ef1d3a3189426cb65e34cd049eebe0cff05919c60e9c2a33f402b0d7741313875dab820e03166ef101214a81c7cb0207408bf36d17ed76420eb1a0579fb44db87a81c8817e1d9ba3f00a36f8b4ce3061786e172e0330f9309c7af90fd2c58df5a1e1dee48faa88ac4ac20e4b31f55c754f8acbe0a9ef75ed4866e99f281eada220e35cd0593d1d5f2195eb04cf5cece5a41cbc4dabb6e981a3a02bf9a1ba855601bb5afa
#TRUST-RSA-SHA256 3531495dd313c1a67035d2c05ed7776a0358d3c42488f96d2dbf26d10ce6de148ee810107e9bf71ab6e732892d944bb9c624f4576cc7deab65206b70b384a5c504fde473acb6c24c1531bca690f116e4b4854c5b478c5ffa7f20613995242355fb7d2bce69f5d05e075977a9ff155e4dec91fa62c35b3218d6fa6e0656380a3114465c16d83d77ee70a05f36089cde180185f6e29e1061bd91fbbdb1ab4164a2259f5d7fef46e4383de41d495bc11df680a1551e0cc3441578dc54dadf529b544a3c62bb4a6856b38644058c56b85bf56f84f06d4afc3f7fc8c21538194658b11e522c2af913d1316cd2834af9c9f10d91cd3b85b46bdcfdad5cd2efc7e8a550f0b07bc84ebe4357fe5ea0d9cd519ac070cb7ba0c840b16abd2a2ccf5027822bde4fc5b9bec19b90127d58331fadfd438e89d6ffa9ce07a28a5c7488b287b9a2aa8849f3d772960c90cbc6ac1b161fc5e87688e3acd1f282a3475c143621ff9194ff83eac9fb7ca2b7b5c752f1223ee25d4c3944aa4072d3c150506855389a1eedae4feff150ef44b1fe6c9d8f844061735d5f072f5482438e37961bc127ef9c094fbd8b444304a0863fd3eebd31706b57469a536b620f2c85ca62e443d202d6c6c231849a6f980a734edb24f85992ff5ad747ba30775a1c942c6b3b709dd8335bfae34b4a39d054ba734135593c1ae2689865b1bf67c50f03dc36a1df341fd5
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(206715);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/20");

  script_cve_id("CVE-2024-20469");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwj97491");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ise-injection-6kn9tSxm");
  script_xref(name:"IAVA", value:"2024-A-0544-S");

  script_name(english:"Cisco Identity Services Engine Command Injection (cisco-sa-ise-injection-6kn9tSxm)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Identity Services Engine Command Injection is affected by a vulnerability.

  - A vulnerability in specific CLI commands in Cisco Identity Services Engine (ISE) could allow an
    authenticated, local attacker to perform command injection attacks on the underlying operating system and
    elevate privileges to root. To exploit this vulnerability, the attacker must have valid Administrator
    privileges on an affected device. This vulnerability is due to insufficient validation of user-supplied
    input. An attacker could exploit this vulnerability by submitting a crafted CLI command. A successful
    exploit could allow the attacker to elevate privileges to root. (CVE-2024-20469)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-injection-6kn9tSxm
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1272cc7c");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwj97491");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwj97491");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20469");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(78);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/09/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ise_detect.nbin");
  script_require_keys("Host/Cisco/ISE/version");

  exit(0);
}

include('ccf.inc');
include('cisco_ise_func.inc');

var product_info = cisco::get_product_info(name:'Cisco Identity Services Engine Software');

var vuln_ranges = [
  {'min_ver':'3.2', 'fix_ver':'3.2.0.542', required_patch:'7'},   # 3.2P7
  {'min_ver':'3.3', 'fix_ver':'3.3.0.430', required_patch:'4'}    # 3.3P4
];

var required_patch = get_required_patch(vuln_ranges:vuln_ranges, version:product_info['version']);  

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_WARNING,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCwj97491',
  'disable_caveat', TRUE,
  'fix'           , 'See Vendor Advisory'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  required_patch: required_patch
);
