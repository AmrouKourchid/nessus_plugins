#TRUSTED 1399ec01a6500fae61ad4320eefad2e0738195121e628ca4f5db53478e5bc2f7ae6ae361d0b5bd4ebcbbde80b295b53e58f0ad7aebdf898e826532c377b156361e6fe35da5397f8e6381a7c25e718353fb6dccf26393b99c5c9fbf7d33f3c4fd6f4d23ea5f054bdb4f7b5d2764393396d1006896f315210d9951ace40426937b790e419ba031389042ec00f8ed43eeb4717aabf48ccdc742665c38b28e5fe3588362a914f280426f71907d91700c6acf510890fcb350b51ea227f523bd27601d259a53ae8d87b64b953ea370069f73d1b4d77325e802ef06ac9cdd3f564cc090946155e5c2c4ff31858712d1d31676b2ad3de543de91aa3690127bd0d36b0bc27d90a7d13a3ce48a7c453fa99a78755e1f3a9767fe53471635a08cc5053251cc0449ccc1a2c79c7da2bd70ca1f906c1fa399143325ae5ffdfcbfeea832008f19854727e3b244921c15e0916477c9a105748122e89398ad0016f72d7380c78a32a1b2a2538b7dab20c5d2eff693fe5091da310943c272f4b65094456b216507125a4ad84a2dfd8823d22ec8f91662da962cc7fb9759eb23d2a1c7cbee29bad3d0498049ab1204bda6e974556d3f8a740be4958540541c05423153bf241227ad9301239f1deb18a2fe9504f5730a67f2d12371da8671f9bff492ed949cdbf5881cecbdf90b4fceba71f5372055feed1efd1ce9d8028b02c9c4fd2e44f0408e1057
#TRUST-RSA-SHA256 a4b65363e2e2100ca9e37861223648151c485215e1c9b8b009ff4f5c0bbbe0828d63163e5010ab10b1394b1b5f290c56ff419965ee31e239324243a66ab16a368b7c1e708e47c9ffa2d592c966e6b0cb3fe17793f881bd01878da590ac96ac42ad072201d35fa9a53f4ceaee35b40061d84f435c32b0e0635ef99f38ff65bfd76df334b0227b15920e5b0cefb4d42bc97206d82cc8b74dfa553ec6536ab8bd72af20f58c7d448d46b73ad657ca79b0bc00fa4e380ded32ff072578a44b6db1a770b78f9adb8235c31ed05e5d1efcf5fd3d83cb465a8999e9a984a3458d41d80b0dce4db8893762abf8c0db3b5f7c3c1dc936a935c1cc1aad6895d852d02e25b5ce629c8f25432673c11712305cce0ec7c0a945932dad17ceb99affb37c66c2dfabf383a655215a2c28c88afa0582d2a98177b44527963325d9b13606676863db8b1421aa2e3ee2ee91c5dfab555e5eec9514cfb214f124f73cb50e435e00c78b11a68c9200e5da07a5d07a852274c826d3ef2f245ca69993af83d44de95287cb8ad88cf9a24f02e3f1640f894d5419b850dcf52889f3d02ddb31966042080aa144b1875a567ab440bc691325ebe3f41a8be2399cb5ede8928a0ebbb278556770de87bf4b43d86a2fd408ef1194faa8580d4657a670895307c2cb2bcf3e9cb40580b031f31ac49b12228c730bfe44bbd19a72a6cc3d3a53c4653da10d8fcb023b
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(206717);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/23");

  script_cve_id("CVE-2024-20284", "CVE-2024-20285", "CVE-2024-20286");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwh77779");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwh77780");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwh77781");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwi52362");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwi52363");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwi52365");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwi52380");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwi52383");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwi52460");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwi52461");
  script_xref(name:"CISCO-SA", value:"cisco-sa-nxos-psbe-ce-YvbTn5du");

  script_name(english:"Cisco NX-OS Software Python Sbox Escape Multiple Vulnerabilities (cisco-sa-nxos-psbe-ce-YvbTn5du)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco NX-OS Software is affected by multiple vulnerabilities.

  - A vulnerability in the Python interpreter of Cisco NX-OS Software could allow an authenticated, low-
    privileged, local attacker to escape the Python sandbox and gain unauthorized access to the underlying
    operating system of the device. The vulnerability is due to insufficient validation of user-supplied
    input. An attacker could exploit this vulnerability by manipulating specific functions within the Python
    interpreter. A successful exploit could allow an attacker to escape the Python sandbox and execute
    arbitrary commands on the underlying operating system with the privileges of the authenticated user.
    Note: An attacker must be authenticated with Python execution privileges to exploit these vulnerabilities.
    For more information regarding Python execution privileges, see product-specific documentation, such as
    the section of the Cisco Nexus 9000 Series NX-OS Programmability Guide. (CVE-2024-20284, CVE-2024-20285,
    CVE-2024-20286)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nxos-psbe-ce-YvbTn5du
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ac7296b4");
  # https://sec.cloudapps.cisco.com/security/center/viewErp.x?alertId=ERP-75417
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0fd3f483");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwh77779");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwh77780");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwh77781");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwi52362");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwi52363");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwi52365");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwi52380");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwi52383");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwi52460");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwi52461");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCwh77779, CSCwh77780, CSCwh77781, CSCwi52362,
CSCwi52363, CSCwi52365, CSCwi52380, CSCwi52383, CSCwi52460, CSCwi52461");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20286");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(653, 693);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/08/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/06");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Settings/ParanoidReport", "Host/Cisco/NX-OS/Model", "Host/Cisco/NX-OS/Device");

  exit(0);
}

include('ccf.inc');

if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

var product_info = cisco::get_product_info(name:'Cisco NX-OS Software');


if (('Nexus' >!< product_info.device || product_info.model !~ "(^|[^0-9])3[0-9]{2,3}") &&
    ('Nexus' >!< product_info.device || product_info.model !~ "(^|[^0-9])7[0-9]{2,3}") &&
    ('MDS' >!< product_info.device || product_info.model !~ "^9[0-9]{2,3}") &&
    ('Nexus' >!< product_info.device || product_info.model !~ "(^|[^0-9])9[0-9]{2,3}"))
audit(AUDIT_HOST_NOT, 'affected');

var version_list = [];

if ('Nexus' >< product_info.device && product_info.model =~ "^3[0-9]{2,3}")
{
  version_list = make_list(
    '6.0(2)A6(1)',
    '6.0(2)A6(1a)',
    '6.0(2)A6(2)',
    '6.0(2)A6(2a)',
    '6.0(2)A6(3)',
    '6.0(2)A6(3a)',
    '6.0(2)A6(4)',
    '6.0(2)A6(4a)',
    '6.0(2)A6(5)',
    '6.0(2)A6(5a)',
    '6.0(2)A6(5b)',
    '6.0(2)A6(6)',
    '6.0(2)A6(7)',
    '6.0(2)A6(8)',
    '6.0(2)A8(1)',
    '6.0(2)A8(2)',
    '6.0(2)A8(3)',
    '6.0(2)A8(4)',
    '6.0(2)A8(4a)',
    '6.0(2)A8(5)',
    '6.0(2)A8(6)',
    '6.0(2)A8(7)',
    '6.0(2)A8(7a)',
    '6.0(2)A8(7b)',
    '6.0(2)A8(8)',
    '6.0(2)A8(9)',
    '6.0(2)A8(10a)',
    '6.0(2)A8(10)',
    '6.0(2)A8(11)',
    '6.0(2)A8(11a)',
    '6.0(2)A8(11b)',
    '6.0(2)U6(1)',
    '6.0(2)U6(2)',
    '6.0(2)U6(3)',
    '6.0(2)U6(4)',
    '6.0(2)U6(5)',
    '6.0(2)U6(6)',
    '6.0(2)U6(7)',
    '6.0(2)U6(8)',
    '6.0(2)U6(1a)',
    '6.0(2)U6(2a)',
    '6.0(2)U6(3a)',
    '6.0(2)U6(4a)',
    '6.0(2)U6(5a)',
    '6.0(2)U6(5b)',
    '6.0(2)U6(5c)',
    '6.0(2)U6(9)',
    '6.0(2)U6(10)',
    '6.0(2)U6(10a)',
    '7.0(3)F3(1)',
    '7.0(3)F3(2)',
    '7.0(3)F3(3)',
    '7.0(3)F3(3a)',
    '7.0(3)F3(4)',
    '7.0(3)F3(3c)',
    '7.0(3)F3(5)',
    '7.0(3)I4(1)',
    '7.0(3)I4(2)',
    '7.0(3)I4(3)',
    '7.0(3)I4(4)',
    '7.0(3)I4(5)',
    '7.0(3)I4(6)',
    '7.0(3)I4(7)',
    '7.0(3)I4(8)',
    '7.0(3)I4(8a)',
    '7.0(3)I4(8b)',
    '7.0(3)I4(8z)',
    '7.0(3)I4(1t)',
    '7.0(3)I4(6t)',
    '7.0(3)I4(9)',
    '7.0(3)I5(1)',
    '7.0(3)I5(2)',
    '7.0(3)I5(3)',
    '7.0(3)I5(3a)',
    '7.0(3)I5(3b)',
    '7.0(3)I6(1)',
    '7.0(3)I6(2)',
    '7.0(3)I7(1)',
    '7.0(3)I7(2)',
    '7.0(3)I7(3)',
    '7.0(3)I7(4)',
    '7.0(3)I7(5)',
    '7.0(3)I7(5a)',
    '7.0(3)I7(3z)',
    '7.0(3)I7(6)',
    '7.0(3)I7(6z)',
    '7.0(3)I7(7)',
    '7.0(3)I7(8)',
    '7.0(3)I7(9)',
    '7.0(3)I7(9w)',
    '7.0(3)I7(10)',
    '9.2(1)',
    '9.2(2)',
    '9.2(2t)',
    '9.2(3)',
    '9.2(3y)',
    '9.2(4)',
    '9.2(2v)',
    '7.0(3)IC4(4)',
    '7.0(3)IM7(2)',
    '9.3(1)',
    '9.3(2)',
    '9.3(3)',
    '9.3(4)',
    '9.3(5)',
    '9.3(6)',
    '9.3(7)',
    '9.3(7k)',
    '9.3(7a)',
    '9.3(8)',
    '9.3(9)',
    '9.3(10)',
    '9.3(11)',
    '9.3(12)',
    '9.3(13)',
    '10.1(1)',
    '10.1(2)',
    '10.1(2t)',
    '10.2(1)',
    '10.2(2)',
    '10.2(3)',
    '10.2(3t)',
    '10.2(4)',
    '10.2(5)',
    '10.2(3v)',
    '10.2(6)',
    '10.2(7)',
    '10.3(1)',
    '10.3(2)',
    '10.3(3)',
    '10.3(4a)',
    '10.3(4)',
    '10.4(1)',
    '10.4(2)'
  );
}

if ('Nexus' >< product_info.device && product_info.model =~ "^7[0-9]{2,3}")
{
  version_list = make_list(
    '6.2(2)',
    '6.2(2a)',
    '6.2(6)',
    '6.2(6b)',
    '6.2(8)',
    '6.2(8a)',
    '6.2(8b)',
    '6.2(10)',
    '6.2(12)',
    '6.2(18)',
    '6.2(16)',
    '6.2(14b)',
    '6.2(14)',
    '6.2(14a)',
    '6.2(6a)',
    '6.2(20)',
    '6.2(20a)',
    '6.2(22)',
    '6.2(24)',
    '6.2(24a)',
    '6.2(26)',
    '7.2(0)D1(1)',
    '7.2(1)D1(1)',
    '7.2(2)D1(2)',
    '7.2(2)D1(1)',
    '7.2(2)D1(3)',
    '7.2(2)D1(4)',
    '7.3(0)D1(1)',
    '7.3(0)DX(1)',
    '7.3(1)D1(1)',
    '7.3(2)D1(1)',
    '7.3(2)D1(2)',
    '7.3(2)D1(3)',
    '7.3(2)D1(3a)',
    '7.3(2)D1(1d)',
    '8.0(1)',
    '8.1(1)',
    '8.1(2)',
    '8.1(2a)',
    '8.2(1)',
    '8.2(2)',
    '8.2(3)',
    '8.2(4)',
    '8.2(5)',
    '8.2(6)',
    '8.2(7)',
    '8.2(7a)',
    '8.2(8)',
    '8.2(9)',
    '8.2(10)',
    '8.3(1)',
    '8.3(2)',
    '7.3(3)D1(1)',
    '7.3(4)D1(1)',
    '8.4(1)',
    '8.4(2)',
    '8.4(3)',
    '8.4(4)',
    '8.4(4a)',
    '8.4(5)',
    '8.4(6)',
    '8.4(6a)',
    '8.4(7)',
    '8.4(8)',
    '8.4(9)',
    '7.3(5)D1(1)',
    '7.3(6)D1(1)',
    '7.3(7)D1(1)',
    '7.3(8)D1(1)',
    '7.3(9)D1(1)'
  );
}

if ('MDS' >< product_info.device && product_info.model =~ "^9[0-9]{2,3}")
{
  version_list = make_list(
    '6.2(1)',
    '6.2(3)',
    '6.2(5)',
    '6.2(5a)',
    '6.2(5b)',
    '6.2(7)',
    '6.2(9)',
    '6.2(9a)',
    '6.2(9b)',
    '6.2(9c)',
    '6.2(11)',
    '6.2(11b)',
    '6.2(11c)',
    '6.2(11d)',
    '6.2(11e)',
    '6.2(13)',
    '6.2(13a)',
    '6.2(13b)',
    '6.2(15)',
    '6.2(17)',
    '6.2(19)',
    '6.2(21)',
    '6.2(23)',
    '6.2(25)',
    '6.2(17a)',
    '6.2(27)',
    '6.2(29)',
    '6.2(31)',
    '6.2(33)',
    '7.3(0)D1(1)',
    '7.3(0)DY(1)',
    '7.3(1)D1(1)',
    '7.3(1)DY(1)',
    '8.1(1)',
    '8.1(1a)',
    '8.1(1b)',
    '8.2(1)',
    '8.2(2)',
    '8.3(1)',
    '8.3(2)',
    '9.2(1)',
    '9.2(2)',
    '9.2(1a)',
    '8.4(1)',
    '8.4(1a)',
    '8.4(2)',
    '8.4(2a)',
    '8.4(2b)',
    '8.4(2c)',
    '8.4(2d)',
    '8.4(2e)',
    '8.4(2f)',
    '9.3(1)',
    '9.3(2)',
    '9.3(2a)',
    '8.5(1)',
    '9.4(1)',
    '9.4(1a)'
  );
}

if ('Nexus' >< product_info.device && product_info.model =~ "^9[0-9]{2,3}")
{
  version_list = make_list(
    '7.0(3)F1(1)',
    '7.0(3)F2(1)',
    '7.0(3)F2(2)',
    '7.0(3)F3(1)',
    '7.0(3)F3(3)',
    '7.0(3)F3(3a)',
    '7.0(3)F3(4)',
    '7.0(3)F3(3c)',
    '7.0(3)F3(5)',
    '7.0(3)I4(1)',
    '7.0(3)I4(2)',
    '7.0(3)I4(3)',
    '7.0(3)I4(4)',
    '7.0(3)I4(5)',
    '7.0(3)I4(6)',
    '7.0(3)I4(7)',
    '7.0(3)I4(8)',
    '7.0(3)I4(8a)',
    '7.0(3)I4(8b)',
    '7.0(3)I4(8z)',
    '7.0(3)I4(1t)',
    '7.0(3)I4(6t)',
    '7.0(3)I4(9)',
    '7.0(3)I5(1)',
    '7.0(3)I5(2)',
    '7.0(3)I5(3)',
    '7.0(3)I5(3a)',
    '7.0(3)I5(3b)',
    '7.0(3)I6(1)',
    '7.0(3)I6(2)',
    '7.0(3)I7(1)',
    '7.0(3)I7(2)',
    '7.0(3)I7(3)',
    '7.0(3)I7(4)',
    '7.0(3)I7(5)',
    '7.0(3)I7(5a)',
    '7.0(3)I7(3z)',
    '7.0(3)I7(6)',
    '7.0(3)I7(7)',
    '7.0(3)I7(8)',
    '7.0(3)I7(9)',
    '7.0(3)I7(9w)',
    '7.0(3)I7(10)',
    '9.2(1)',
    '9.2(2)',
    '9.2(3)',
    '9.2(3y)',
    '9.2(4)',
    '7.0(3)IA7(1)',
    '7.0(3)IA7(2)',
    '7.0(3)IC4(4)',
    '7.0(3)IM3(1)',
    '7.0(3)IM3(2)',
    '7.0(3)IM3(2a)',
    '7.0(3)IM3(2b)',
    '7.0(3)IM3(3)',
    '9.3(1)',
    '9.3(2)',
    '9.3(3)',
    '9.3(1z)',
    '9.3(4)',
    '9.3(5)',
    '9.3(6)',
    '9.3(5w)',
    '9.3(7)',
    '9.3(7k)',
    '9.3(7a)',
    '9.3(8)',
    '9.3(9)',
    '9.3(10)',
    '9.3(11)',
    '9.3(12)',
    '9.3(13)',
    '10.1(1)',
    '10.1(2)',
    '10.2(1)',
    '10.2(1q)',
    '10.2(2)',
    '10.2(3)',
    '10.2(2a)',
    '10.2(4)',
    '10.2(5)',
    '10.2(6)',
    '10.2(7)',
    '10.3(1)',
    '10.3(2)',
    '10.3(3)',
    '10.3(99w)',
    '10.3(3w)',
    '10.3(99x)',
    '10.3(3o)',
    '10.3(4a)',
    '10.3(3p)',
    '10.3(4)',
    '10.3(3q)',
    '10.3(3x)',
    '10.3(4g)',
    '10.3(3r)',
    '10.3(4h)',
    '10.4(1)',
    '10.4(2)'
  );
}

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_WARNING,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCwh77779, CSCwh77780, CSCwh77781, CSCwi52362, CSCwi52363, CSCwi52365, CSCwi52380, CSCwi52383, CSCwi52460, CSCwi52461',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
