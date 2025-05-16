#TRUSTED 2f221b8ff56fcb9cb17c5d99c8dddc080323c68c838311d65b54acffa486af224e3c5a48708d266a058c50b3159f4297e0af177cddde2641635250fcf093cd1277fe3213139275652c1117cb4ad4f4d61d3a6ccd61bcd198b84a55eba39e4e742a566463233b1423e92c3364d2d528986b720e777dff5f3bf49ba78eb9b3c966ae057cd16134209944bf2fe97af55fca67a15b5348a008d023d1602d2a5437540c3ff4df7be6a8bf049aab13094e975b97376d5987a939143fe2a14d66f46f5d1d7b5ce8d014f4bcbf9cd404bba4ecbbd9961c837d84bf98f030b9b4633ce1a8e5b357b025e872611cf5a4ddf2ccb6fdecb7c42be0922aa0187d147ec6b5f0e7294302da1ab6f59507f0dcf37cb2a5022e48b855c31c73810cb5bcce29d931a2c54f619493773506c7c1c552dc107811c8b0f1507df16c90fcac8b2f6d3993e9c8a7146e059214f94bb99117fae177c2458fb26351213e74f92a467a6c6a83f116de33cbc099e5cdc4ee25758a7e497a6ea4dc03194d085f2ec3e06a02e8be66e1c2322dda707d3f42879ca1274c0673ff8f60bf96095e5bec2bb1c6406094e2ee94422d96b5e6019e0db08f678a8517a6e56b812fa2471fc5de3715334309133ca829563d231411ece435c52b7a504f3218332aa764a37caf9d0c9bf709422707eeb00bfc272c6e31ed397494a12e431ed3545b13ca72b25e86adc731abdde0
#TRUST-RSA-SHA256 6c41c798499d2eca5584c6bbfec3a985e14978990a37eda2e21949413361c68fc031f7b5a17de27b6fe0494e2ed7af6f4a07f372c6e4a6a73ad5a115aa6f6a0f674774fe44f3de3b7efcec7b12bd60d66743cdc6ecad3c0192352e617b8c57c461ea8c52c76129d2c54a7f9fd4085b7507f28089d835f6692b0454bedad2d1872751ce128310e5f9157b6495210b7b751e81fd8c4c7a625fe153d18fe30025e21076386a999309f8dce464a2eebc64ce9009c250ab23a5e57cf3474ec7ab3b25ffa52ca93534728c13c25471332f75505cc126fb349ccc72fbfa380eddb8f00d6758a2a146294f271cd2a480eba868dbfb242f19340c8fee8b1e06d4abb687a453e07c641370622a2de3d97f6039336c0f7a72998bb31bd5214d6de6f136b2aba2248c4558d361365e7b8f18cc7ac4801040e1779a5e8e27e82ce2602ddaf78acb3b07f4de15ac70eabc6a60f7ab128ae99027f4b6e05e22b56ba995ae6b7df60c80a6a2c98cb4850d6350568e54913b8c082d7246dbe98babe4713ab8060cbee7b565e811e5e153e424650a3c85985f77102e52573f60b137e03750c8983e84b9b10291775457a9f8917193ebc648a89fc908ff9ccb82b681e3b92c7d733c531662b564df79a0052945eae1c171f62538cef0e225e6028d0e22a42944be9353ca019caebe4137edca127c9d01d3bbfb21ce499a5d0dfe108fa1efbb45ae7676
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(184196);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/02");

  script_cve_id("CVE-2023-20175");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwd07353");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ise-injection-QeXegrCw");
  script_xref(name:"IAVA", value:"2023-A-0595-S");

  script_name(english:"Cisco Identity Services Engine Command Injection (CVE-2023-20175)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Identity Services Engine is affected by a command injection
vulnerability. A vulnerability in a specific Cisco ISE CLI command could allow an authenticated, local attacker to
perform command injection attacks on the underlying operating system and elevate privileges to root. To exploit this
vulnerability, an attacker must have valid Read-only-level privileges or higher on the affected device. This
vulnerability is due to insufficient validation of user-supplied input. An attacker could exploit this vulnerability by
submitting a crafted CLI command. A successful exploit could allow the attacker to elevate privileges to root.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-injection-QeXegrCw
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?22798cd5");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwd07353");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwd07353");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20175");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/11/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/11/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  {'min_ver':'3.1', 'fix_ver':'3.1.0.518', required_patch:'6'},
  {'min_ver':'3.2', 'fix_ver':'3.2.0.542', required_patch:'1'}
];

var required_patch = get_required_patch(vuln_ranges:vuln_ranges, version:product_info['version']);

if (empty_or_null(required_patch))
  audit(AUDIT_HOST_NOT, 'affected');

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_WARNING,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCwd07353',
  'disable_caveat', TRUE,
  'fix'           , 'See vendor advisory'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  required_patch:required_patch
);

