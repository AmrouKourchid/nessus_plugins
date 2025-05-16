#TRUSTED 16258c09defcbe34d5b14817462a92f8dd8828c51d0cdc68d6631d453e54f8bcc18212970c230132d734366242b3664990d59d52770165dd01b3378e90814af99e6196d3ecfb13154211a3d9cb38d81848c35709e5be2885b4f40f9d7a4b82a31f2edd128f6cca7336d5d22c7ed1ac3b6f46a9e6ef093069e6971fde42280f80eb27e59118b3e3efc38e6d1d95d00fa52566f844f6a0d122c40ac8c794a581900065180c1ca6acc9fa6f8530d6df565b72c4cad0b7e930d80b5509bd957202f4a4231b48292849113f7cce47f1edd664bff8b890c26980bfda26b6ff38e87bacbfd4d81b10d0950b7dcbddaf49587bd873992fd039e5caf2487b1f766307ec684e21e16c868cc8b3c7fdfdf078d1d98b8e116d2bcb9f1131bf407aa8d2a96589a7b06a4126b7e0e529722d1de6e1da0cb2ce9971569437d2ceea55e3149926ee2efbaecadd8e804999b38b7cd12bd9660ba0e2a7af52e8a94a47ee3c7167084514fd8946783a9d201d9a5e8c4e64aa385732c0db325d623897bc707c73784d5dd530fdedff8e86f15ece530de02ab7413cbcf54e4272188d6b37185b7c37fa402aadd7e89fa3c4de24d6cc2d02d3bc230f37a4b037f527abb9f7163502a806c2e8fb9ecff22896d22b1e3e53bda3db2ac60624b8a4e6f0bfb73624672ba00d618765dc121e4484fe14cef5bef79195fccac7f739c638bc61d68f8a9aaf00a019
#TRUST-RSA-SHA256 67587565d85a999d79dab638ede02beb0ebc0bd2a90ca7ecaf0ec99d0252b76d5c3fe625f9a061ab8dde8d1a5964f6af63fa5eb11cb7b9c4c9e3aec85cc1f472e055c88a05d3f83d3d1aa082004a5ca0e3b210490adf12e791eb12506897bd5b11949bd9c9481df4b5323c8d529fd62d6f779d549b0cb30ed7bc9cd8a249ccb2c9e8b28323315748c2262f1e15b79ee0ed8392cd793a84000394bf42f5122570e7d82d0ee28e17ab6d36b0efcac7ccf779e7165c84158de79fb4d8ab2c323b1bbacbcc729d2eb63d4e17a0407ab48d593dca3c76df5c5b3a4b268541362d22d63520626c663dbafe54043f8cdba1e9b9cd7d0adf4399132a0718296124f5fd0feaf765128849e9d2ab20c75b5663ed195c29a40d60aae2e08b247b4b3cfb15d462dbc5899d40c434602062d2f4583c4ba2bd201f178156ac8fb191997773e17f373cf71cf2bad0a961816a83f14e2ebdf20caf309c5a83cb47def87468dd57e7f67a7ecfe0f2361519eca3a9a3b0dc15217409681fcf30923886373fa682b1d6aa0c355c010e2ba2ff23b59a9e89733092c7d3bb964a8131d09e4c15c250a08d146d3996032f3a7fe465ef1725d31d3c43c18024c5897ecc636ce6ba4f100b748017cb4cd0bfbdef5e823b170dcd3985e38bbb1eacc8990afe3b6c492d909fc74417cdb5a1607957a2a925900e58af9dafe5e9085eec1c8ffba1086105e68606
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148094);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2021-1383", "CVE-2021-1454");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvk59304");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw64834");
  script_xref(name:"CISCO-SA", value:"cisco-sa-xesdwpinj-V4weeqzU");

  script_name(english:"Cisco IOS XE Software SD WAN Parameter Injection (cisco-sa-xesdwpinj-V4weeqzU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS-XE Software is affected by multiple vulnerabilities. Please see the
included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-xesdwpinj-V4weeqzU
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e0f0c4f8");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvk59304");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw64834");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvk59304, CSCvw64834");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1454");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 88);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/24");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/SDWAN");

  exit(0);
}

include('ccf.inc');

get_kb_item_or_exit('Host/Cisco/SDWAN');
product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list=make_list(
  '16.9.1',
  '16.9.1',
  '16.9.2',
  '16.9.2',
  '16.9.3',
  '16.9.3',
  '16.9.4',
  '16.9.4',
  '16.10.1',
  '16.10.1',
  '16.10.1a',
  '16.10.1a',
  '16.10.1b',
  '16.10.1b',
  '16.10.1c',
  '16.10.1c',
  '16.10.1d',
  '16.10.1d',
  '16.10.1e',
  '16.10.1e',
  '16.10.1f',
  '16.10.1f',
  '16.10.1g',
  '16.10.1g',
  '16.10.1s',
  '16.10.1s',
  '16.10.2',
  '16.10.2',
  '16.10.3',
  '16.10.3',
  '16.11.1',
  '16.11.1',
  '16.11.1a',
  '16.11.1a',
  '16.11.1b',
  '16.11.1b',
  '16.11.1c',
  '16.11.1c',
  '16.11.1s',
  '16.11.1s',
  '16.11.2',
  '16.11.2',
  '16.12.1',
  '16.12.1',
  '16.12.1a',
  '16.12.1a',
  '16.12.1c',
  '16.12.1c',
  '16.12.1s',
  '16.12.1s',
  '16.12.1t',
  '16.12.1t',
  '16.12.1w',
  '16.12.1w',
  '16.12.1x',
  '16.12.1x',
  '16.12.1y',
  '16.12.1y',
  '16.12.1z',
  '16.12.1z',
  '16.12.1z1',
  '16.12.1z1',
  '16.12.1za',
  '16.12.1za',
  '16.12.2',
  '16.12.2',
  '16.12.2a',
  '16.12.2a',
  '16.12.2s',
  '16.12.2s',
  '16.12.2t',
  '16.12.2t',
  '16.12.3',
  '16.12.3',
  '16.12.3a',
  '16.12.3a',
  '16.12.3s',
  '16.12.3s',
  '16.12.4',
  '16.12.4',
  '16.12.4a',
  '16.12.4a',
  '16.12.5',
  '16.12.5',
  '16.12.5b',
  '16.12.5b',
  '17.1.1',
  '17.1.1',
  '17.1.1a',
  '17.1.1a',
  '17.1.1s',
  '17.1.1s',
  '17.1.1t',
  '17.1.1t',
  '17.1.2',
  '17.1.2',
  '17.1.3',
  '17.1.3',
  '17.2.1',
  '17.2.1',
  '17.2.1a',
  '17.2.1a',
  '17.2.1r',
  '17.2.1r',
  '17.2.1v',
  '17.2.1v',
  '17.2.2',
  '17.2.2',
  '17.3.1',
  '17.3.1',
  '17.3.1a',
  '17.3.1a',
  '17.3.1w',
  '17.3.1w',
  '17.3.1x',
  '17.3.1x',
  '17.3.2',
  '17.3.2',
  '17.3.2a',
  '17.3.2a',
  '17.4.1',
  '17.4.1',
  '17.4.1a',
  '17.4.1a'
);

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'bug_id'   , 'CSCvk59304, CSCvw64834',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
