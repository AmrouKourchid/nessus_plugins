#TRUSTED 628726b8200078e622c487df2c121b3d553c423780f4e5a2370b92f044d4dcbc217a34e1d11ef5afae782ca334a4bbe7f0ef546ffc9d7fe9bc45f30ab446ff24f4ee8b4ec425afb3cbbe92efffd28135e98c5798bffe7f74657c662a01a13fa4bf8c7b4d3e460d114121401ffe2338159232f50782fbe259f50a5bd1534cf762327711189402884a88518686679877431a8b5bea58e53e3563ac22441aade7bf057043c0103d022ef123b782e3a2bf95c05361d5bf924fbb9d58069aaaedfaac6cb5c761629c8ffd6ceb0ffe55fdc684d73974a056f2a74932e4d08f5bf81e159bc48a6220d2ce5f9d2b6fe9107758fdfd53b98e2c6e36f902d06d9e45d27f2afe71e935e0a63faadea300f2998829a0a52c412a589f7c8203e17845690d50c50cc0269469a3072d3777656f8466e624489edb183a27e4df3b78aa401327eb0a1560e1fe8259953b7c6c6c1fd8c144e7e9be883f829da8a7056a2042bebe0de225a093621698c20572ff359ace7b23494302dd5a0c5eda8d5245515f5992a493f5f874dc751a59235ac562848e79f5d1adc96532798f1692cd31ab62fb173b6064f11edad3cad02edfc10fb869b4369b51da8a11273f3546bebded309fd81d5e25ecfbcb043ba425a46a63348aca9cb05d85ad3503a21922f5eb68860bcea7be0252c84b862cca09a3e023a996a6a26af18ae12bc120cdf9a257b96f0baa2035
#TRUST-RSA-SHA256 32956f4e2b14ef4fe1f5e95618e8a20b9392a88882f3f5f742cd3c889c13cfd6811cf0cc84acc043ef5d3e274d5d2542557214a4d26702add9e666262cce50c9ee6ac1ddd8e44c9288900f3cbd7bbb73089e17c07f4ebb474505f4f6e823620138abe1dc74fc559ab4d61a97d875afdf686a648962bee7eefb5db318eaf4d44224e939b84c5d3e3e6bec06fbb67b3bcd76a3fa566d149ff2b65d1ff74e5e3c7c174fda235665a147c293fce924e59a0f391a7809cf214a7b61c428df66b82f93335f6f61a05a078ecde39fe62a2da6ffbb0d1f8d2350e0fef218daf02a499cee12e2ce2693ac8910447a3c19493dbb1b1f6f9514ace4f115997e8d0cb7d7f95e71e38c880ed0613dd4558701b7eae3fc65337178c718edea7b575e491fe01e4c44dab261c31d28d0fd875c7499a563cde62217726056c2699b1c45c4bae6645950c97f8b8b91e71ed9cd97f47b15c529a5e9eeb13bdc7a5ea2371848adc21d6bccaa6030a9a008b8c6949217d12296bbab5db14f5671ca535975d8fe292f427b2ee4b0a5ba6e9c9714554e420a767845c283d1a9bce2659e6f86ed5a69664b23653537732c9728a1be7883bf424b8b5e7ed156c3978abe0d2d8e62e3c5ca3abea59315e2a00fdde1086316ea5f9e24521a44fc222a3b05e402ead634b7f6d1003c1b3d7a4805728d69ff04ce5b6c0291360abf80ab597f17d0aede30f71d1430
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(166918);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/09/21");

  script_cve_id("CVE-2022-20960");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwc35162");
  script_xref(name:"CISCO-SA", value:"cisco-sa-esa-dos-gdghHmbV");
  script_xref(name:"IAVA", value:"2022-A-0463-S");

  script_name(english:"Cisco Email Security Appliance DoS (cisco-sa-esa-dos-gdghHmbV)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Email Security Appliance is affected by a
denial of service vulnerability. This vulnerability is due to improper handling of certain TLS connections that 
are processed by an affected device. An attacker could exploit this vulnerability by establishing a large number of 
concurrent TLS connections to an affected device. A successful exploit could allow the attacker to cause the device 
to drop new TLS email messages that come from the associated email servers.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-esa-dos-gdghHmbV
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?49ceb9f4");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwc35162");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwc35162");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20960");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/03");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:email_security_appliance_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:email_security_appliance");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_esa_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Email Security Appliance/Version");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Email Security Appliance (ESA)');

var vuln_ranges = [
  {'min_ver' : '12.5', 'fix_ver' : '14.2.1.015'},
  {'min_ver' : '14.3', 'fix_ver' : '14.3.0.020'}, 
]; 

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_HOLE,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCwc35162',
  'disable_caveat', TRUE,
  'fix'           , 'See vendor advisory'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
