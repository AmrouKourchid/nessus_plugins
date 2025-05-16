#TRUSTED a68b3f69a252d51474d34e8bb953e0015bf2123cf89d049526a3ee445a3ad674809ff4466817e423db34a196466cf3313e919b5c4c845944dcd022d6cc3d9e7e89ea03fb5d34b675dff682ddf690cdfca423bdf1c383e173a8522609efbc78cfaa61159e519efb4128fcf9515f4afcc0f1b02f9a4218a86fc2b136472c552a442da7a9169e408eebca9065b459e7d07870e803c372ff352557eb27174fd6f41e13d97129910ae9f43b2c70ab7f35d369d8996faf2ebd6cd6e500db3c779721067c2c15dfcfeee7c245999ceb2686d231e152ac0c71ed31f51962689bd00bdb4d940a81715874ee21b5a2f0fe39dcdc3fc6ca784714baf880c316507eb497f6122b13cb2e09220c6d5764bb84b9014a46cd5413778db086445f334586d3344e891a8629e27ca94d3a8c250492da401b24e4a36e7e0776d7a27d02ad1d41a041843af281ff10716a77f83b284dc7d35d34654d6d2661c3c2446739ca94ee436d9ace55ceb1d8b26253acbf21a183019e03d9de2d30bf6dca2b03eb28c8a9acf7202c3d32fa372a6acb01c139ae1130848a8ea646605ffe3591de3e583a008b943ffee7299f336e121f84f663067dd3ff13580753835bbf26a8b59b2bdf869bb4609cb81780c9d982e9a2dbc67195285d0e4be493eaec48ec4e3f0b76fe2f889620ffdf5426256ed424a3cbb0aa7596b24edb932d6fe61388eb5356010141b33502
#TRUST-RSA-SHA256 17567df606afeb1a564b7811626860d276126090af9381bdad8b91f4f17271ee2544bef45be603710e1db60a375c9c4aae596d4d44ab0197ec4065b78e27fa55869f0a28f429670601c47a15a13ec0b91f6806f2ead5ad445b7924d05ab0aef59ba8605b1159aef592fd6901d26c522127b4b8542aa6c1b89579c160b541c28712572ea54575a9ee59cb814fa84055f0e314b7071f19f0f6c4d6df7fcf80a85704b0b18d97ff381547fcdb9437df65afba1e86179a17ae69c85a1320a2917398ff9b728ae09c90d5d46a5cb12a004770046a01bcfb31e5fd4a0fdbbc2ed719b779d5e04b34667793b0c184911c476b2bb61bd251f889f3b60ba19adfdc20b6b8850ee0f24eb88712a45d607f51be83976d130692a2cc735d378b3b8507129dd3716064793231734462d4fa6297709385fac9d807a86474ee3e2492ede1cb1fed96163704a30866bfe8b8f560c5855ca8810f46cb4788b64cf4ce61360bbe290398497b2e09c3dfde3efe2b33932250cdf5b2a6bcb73a451be3e12e21af12d976d3baee3af8ed24d88ab059d9c7031621360e0f14e720f47baa15657954e534b11d82b48aafb49be77bfbef2a0b725b9fbdd990678e66d4c0786135c411aa9e11cd54a8a882c0769abbdf1d1c565db25fb98c07d426bc4cb9f3a25b670820bbb3c8dfc54849174a361f3c54156aee331be2985eb47984fb64e52d5327fc9bc2cd
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(235486);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/09");

  script_cve_id("CVE-2025-20147");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwm49535");
  script_xref(name:"CISCO-SA", value:"cisco-sa-vmanage-xss-xhN8M5jt");
  script_xref(name:"IAVA", value:"2025-A-0316");

  script_name(english:"Cisco Catalyst SD-WAN Manager Stored XSS (cisco-sa-vmanage-xss-xhN8M5jt)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN Viptela Software is affected by a vulnerability.

  - A vulnerability in the web-based management interface of Cisco Catalyst SD-WAN Manager, formerly Cisco SD-
    WAN vManage, could allow an authenticated, remote attacker to conduct a stored cross-site scripting attack
    (XSS) on an affected system. This vulnerability is due to improper sanitization of user input to the
    web-based management interface. An attacker could exploit this vulnerability by submitting a malicious
    script through the interface. A successful exploit could allow the attacker to conduct a stored XSS attack
    on the affected system. (CVE-2025-20147)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-vmanage-xss-xhN8M5jt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?222e61e0");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwm49535");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwm49535");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-20147");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/05/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/05/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/05/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_firmware");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_vedge_detect.nbin");
  script_require_keys("Cisco/Viptela/Version");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Viptela');


var vuln_ranges = [
  { 'min_ver' : '0.0', 'fix_ver' : '20.9.7' },
  { 'min_ver' : '20.10', 'fix_ver' : '20.12.5' }
];

 
var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'bug_id'   , 'CSCwm49535',
  'version'  , product_info['version'],
  'flags', {'xss':TRUE},
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  vuln_ranges:vuln_ranges,
  reporting:reporting
);
