#TRUSTED 89bc223d50fb9f3031a402f436321b0655582585402883256dc3799af9e2c96b2a6baafa6cbfa3eb4f2ab9ecd9ce466d86ea67700f4b68586a08d030264fd4a2d69cd7d68460846270d58a36c05cbfe5ae89f65b40384ffe0c01ddfb7af8c4d59b4ce1b8a02e3939b9d37f0001db143ad0f29b469a44db43996b2335605de343eaa96640b235b3e1aa870b2fd4801c88822474a26adbafc5b4c36b65fd257af557afb23feb323ebaf3ad201f85953d51bfaddde91c127f189817f4e025ac3a7d23b78232939a86e98175e2972abd4fa011d5f483c220b5584da5e5392864a8115e7673944b57b0400a5de1feb4d5de3e6db8599e2317fecdf610b4bf09ef8b6bf93f9e3f4034f397ae306a80b2f464004199589a1bb47c63c42b39c54fac12c15fab3bb64c4a6abeddc10992f191c5fbdee33405bcca78b8092af00b0bb27db717a7f0712edbe295e5637617aa73f6f03ae609ea6546a8fc31c3e32490106867d4cd17f49fe5d64100d0a2efd309607481ccd5f7c028b7911a61bbae24b2e9a52e66864a482b9fef05b03a321dc4184f540bb4df975a5e23dfb3515ce2e6e67114cf4fe7d52f2a75cb26a5f37ece66fd89398d48d968f7ec76da7fda2d3cd9d78ead1a5e28e0440bf6f79d56495ebebf23139c5a45c93cf36b6aa3a87f965c060e05acbae960fa14d295a857d8810abd02bc50f7518e502be8df698772c1bd21
#TRUST-RSA-SHA256 300dd9985b453511fb661b3831b6d3398b7a79414ca034ed650421d8a7c198379e97bc61d8ddd45af64dc26793231f1e20bbc68c9c0e3c422700fb93fdad6291792c29e45f056df09deacf84707b164ce1029dd20050e14e838f411e4db39e447da57fdb93d9bf7a7f38a77843cfad823d91df9b742ba42a2528df9b4922977514d60d27846edfae74fce1d9407bb755f14975dfa00ed0974248726c558ed97a9fa2619a861f0ee98133934e54fc4f2e3516719bd921d3802ad2e2980521c8fe728a5b3a9da65bc84d794f6d2f1a2d22cbabb5465541ea61b00de8fe3b362b45056170f2b5e853b8a4bc99311d12907138a0d58e7bc9ffa0454091505a5975d9141a963f28294c1f0042888bb9b72d966c88566b967ad67aad47bdba2fe50dc59dd97a0a5deaa68fb6f5d8279e44af2fd7c596d79a0d4be6dcb35b11d663f0357d1df9075eafbaec83916f11c41434c25a05cf45416b28a1927bd150f2c7a0241f0ed0c1d181e09a7614e79ac63453775aa1c04ab1ed2811f0ea130c85fdc2bdf4c34672ec2d459a0ac20aaa3bacfac1e2fb9b0c65d9f0e6f7df8e4e1ad09e4e10c509622981f0b8e69fb9c4d342d08a3c81e0e6b9e5b912dbe4ea990c611a882c77f9bce5c9a035cc72abc821b0014ec1a4347d072b1ee74ce935bb58a558ae0f33df4581a4c18884fcf2f81bb2af12b73305dff123df7ad562cebde0658e8f
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(235489);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/09");

  script_cve_id("CVE-2025-20187");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwm04401");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sdwanarbfile-2zKhKZwJ");
  script_xref(name:"IAVA", value:"2025-A-0316");

  script_name(english:"Cisco Catalyst SD-WAN Manager Arbitrary File Creation (cisco-sa-sdwanarbfile-2zKhKZwJ)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN Viptela Software is affected by a vulnerability.

  - A vulnerability in the application data endpoints of Cisco Catalyst SD-WAN Manager, formerly Cisco SD-WAN
    vManage, could allow an authenticated, remote attacker to write arbitrary files to an affected system.
    This vulnerability is due to improper validation of requests to APIs. An attacker could exploit this
    vulnerability by sending malicious requests to an API within the affected system. A successful exploit
    could allow the attacker to conduct directory traversal attacks and write files to an arbitrary location
    on the affected system. (CVE-2025-20187)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwanarbfile-2zKhKZwJ
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cb4f687c");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwm04401");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwm04401");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-20187");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(22);

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
  { 'min_ver' : '20.15', 'fix_ver' : '20.15.2' }
];

 
var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'bug_id'   , 'CSCwm04401',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  vuln_ranges:vuln_ranges,
  reporting:reporting
);
