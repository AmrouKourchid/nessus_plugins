#TRUSTED b13dd6ff1c50254990cbb94430009222f00f0f57281897ccdf75693b6ad8e4f10ab69c09326d66544c57261cf7b0d40f7f9d17300e67b02241fa047b8dca13f10c683d9e08fc8ef3f730052ca93da682b820167ffb56fd110ffcdb1224d4d35f0de45e52db63be01e6288e805e747d003857a3e90314d3c1197121f725d06dd37a8006b28169c624c30d51daf0c906d2cd677e801e0f8cacc4ea6e4a055bf7440cae6e0acb2de5c41178fc83d0aa410d98c0afdb26137e503003a3cea5b9c3eeebe9897c6b4297f29614502a41a80bc33e61c7c263e7fc4ca848af41cb8549a7f2dfe5fc833737277e5de4121a7df86568348bbd966bcf450dad957b28c62ce70c25bf5d068d894926a46adba43547c7b6cf13bc2af0a9295cb78ee29d00bf92febd4494191261120a454ebe57c3ad4d006baf739c17c215cbd68c71178af8bd226130ee5bf0cf684d8e3b41a05be726713544f07fec13cba702c329f9121396ea745cbd72541141270d025fda2437596bd67cf11e3180d0d562c666efcfd8d37317cd68ad2a34120132b3e964a7f5006e6187f154b369c3d65b7258c7f620911be305b3d8c2a797ae4eec16efbe95b9a553f1f6c4fcc61dfc9d3980f0b0b31e3c71d9c4e6e1f5572881b50f9f04e8969a5779e55a925635c14769cda14ff6190091f0f1431d6888d5ce8b4ff9faba9d36d13be424dc9ef5db0c29bd8d041e50
#TRUST-RSA-SHA256 3b184010449e4a9fa6abfd6f8079d6322c718e22f85d7b7f810de56094843d1fe05edc6943780b0d531d96c7178050d54c44c5de5ee5514cc3503b78caa829b8696b25c7ac4f5ea716a993546d3ab4c5d5013738ab8802208808e54ac78ff24a648e2575d46be1f66a0d7105fafef891b4677539dca9e521f4c2e2e0a7d99b78be5537c9daa6952576d89795119421d2a07b96904a068fe36ddb1aae52af3d9893a4dbd9b5a31e16b93e4e17f82edeb3624f92dc2224d76df6497a88ceb312c024fa91dfeaed0a099a18a0bf98adee6b37f6dc51cfdeb1e749639b5717e17a9d6194366a2394977b033b58c3df77b04aa5d287761960fcc07feb8970eaaca33f7a131fc3037964d5098e23ceb1dc089f0dfea693a60ba1b5390d200e135b5ab325c78826ae47d79ae3e5e6d0346c3f40a2d4b5672eb8e9259cc290cccbfb075fbbf49a60427739394303be7b5cd9e7d061b79c5be7500c2a3f9c60dcfcd72310f28020f9f75c134f132b13cbf7cca44752aae5b2f4910f624c438d72ff3f770372d446cc60c8fb5c78af50a0eeccd8e49ff4079160460980135be4ffc8625556c0ddd784d6d5422bccf5ec899a71bd8d4bf02e4a6bb2542975df954dae5e0f3c584f1160e2d133a7501d1be70c3b3c70b9ffd84da91140cccb2a62094cd3c0277e23c84bcc91e8ed7e7b1f7873472b80aa050211b73ba94e2f369061b4b87117
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(138327);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/19");

  script_cve_id("CVE-2020-3431");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu06343");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sa-rv-routers-xss-K7Z5U6q3");
  script_xref(name:"IAVA", value:"2020-A-0285-S");

  script_name(english:"Cisco Small Business RV042 and RV042G Routers XSS (cisco-sa-sa-rv-routers-xss-K7Z5U6q3)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Small Business RV Series Router Firmware is affected by a cross-site 
scripting (XSS) vulnerability in its web-based management console due to improper validation of user-supplied 
input before returning it to users. An unauthenticated, remote attacker can exploit this, by convincing a user to 
click a specially crafted URL, to execute arbitrary script code in a user's browser session.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sa-rv-routers-xss-K7Z5U6q3
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9b6d4ec0");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu06343");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvu06343");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3431");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:cisco:small_business_rv_series_router_firmware");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_small_business_detect.nasl", "cisco_rv_webui_detect.nbin");
  script_require_keys("Cisco/Small_Business_Router/Version", "Cisco/Small_Business_Router/Model");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

product_info = cisco::get_product_info(name:'Cisco Small Business Series Router Firmware');

vuln_ranges = [
  {'min_ver':'0', 'fix_ver':'4.2.3.14'}
];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvu06343',
  'xss'      , TRUE,
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  models:make_list('RV042', 'RV042G')
);
