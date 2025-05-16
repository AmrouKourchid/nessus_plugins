#TRUSTED 12377c3aa2916da67317139c6215dd507862e75c6797da858c150b2fde56bbfcfd1eff9d85da07efa39dff18225cf405c03e65e4548c2c6cbcd95317e1887c485a7505e5a09a271998c242a996d06552f47a3b3e9b9703b09382da9d6095813f714ef763c372f08be9ca0e72d9c086c1faf25e4de4f6fb24a50e0b80a1745776ab2e1a3bc55d47b0cf4961eb47b0161123a1a11062473d5e5b288ff4c3132b9fee1abf476afab4957b4cfb67574fc54947cac8ec7d1834bc1d55adcda9fcf239dd9739577ea57dbb0112961feb78e291c97d70d7b45755cee4ccd421e4e5cc4147465fb1afb68e3558ec37d72b99b18cb7d0aa76b89554729af0f7db86ee773715bad67fc2079f167c60383df66a64f678a84577091193572dfb9a076593a763eb928d5ed9bf6f98d10ca9e0bcf05349ea32acb2bb700a96d2baf218407a82e5c17a22e582b67e1290fad6de5f312b353e4920303c3f0a5b817f16dbcd73cf95fdf6af0735bd5914f0706e9f7f7d919dcfcffb17d5427db710bd7ba9d0a0a77bc889a3ac55682c0f4c724701ca6eaa5d1ef2bb167f14abd8485ac8ad14d8f3818de5299a2de93bba83dd23a72fcde38ae99aeea89a5aaa5a331a9a369683a4f1f98f2b706fa46f5f0cb47130d7f5ae966a2e8a945d249cc490f3e94fb592e1f3538cbb226140f90760b974aeb3de565cc937f22a6f08abda0e49b0f11cf2f598
#TRUST-RSA-SHA256 b2c46ad972c5976f0fa36af85b72491120f6714555af04ef5984971a25ce88c7c4071138c13fc7e32a40c72f1bb002a81e76c7639a77e27dd2d658f884e4767aab7312794af448592824e87f72f472e9c78f7cca0065866418d5f46490b9b8809b9d5c278c3be021c0ff901fb545ff747feede6f099a7a0f3fd57039da05f7b888bff4259ae0064b9071bb8965ff71e22d2dfc3380d5ef78ebfcb739d9c916c2e5fdace3199a931b25de96f8b9c8e3c36fd4101c774fbe05ce9383218bd1ddcb2d91338d4d2d424ff80f6a4e46c871e6e3e2bd0be17a14e7b43b83bd1f84a117997b0b2c5faa78d9b88e6759bef961b289debab99dd0a8b7cfc7494503eb6e35b484b0dbf99d187f41b237e9a46d9634fa2107a7a40fc67f119577e13f53447e15b2fcbf71ea98f82e6885a228fe873377f7a71e30435dc0d95b92d6884317e467179806eceab396f68b0cc0a7308ee48256c42cad6c84a7dccf495174cac549c9b43524a6ae24b0e661be0c0d914b34878f30194a2f0b3162dccfe291c42bb4076b233fbe85835851195c981c334635bbb45fd832e4b7861332f12d87611b48a24b369097aa02492ef7f398d35c401c3152bc3c9dd6aecf219452e36646b1461b11990e003ecf1125f84d729e82d341336ed8b9aced83b2a3e99fd65ad99385b9301467ad322d36309bd9653b4a9e9fab3c1e2e6ec8bd8b06856e8db25a5951
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(186210);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/10");

  script_cve_id("CVE-2023-44487");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwh88604");
  script_xref(name:"CISCO-SA", value:"cisco-sa-http2-reset-d8Kf32vZ");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/10/31");
  script_xref(name:"CEA-ID", value:"CEA-2024-0004");

  script_name(english:"Cisco IoT Field Network Director DoS (cisco-sa-http2-reset-d8Kf32vZ)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"The version of Cisco IoT Field Network Director (IoT-FND), formerly Connected Grid Network Management System,
installed on the remote host is prior to 4.11.0. It is, therefore, affected by a denial of service (DoS) vulnerability,
due to a HTTP/2 protocol-level weakness. The HTTP/2 protocol allows a denial of service (server resource consumption)
because request cancellation can reset many streams quickly, which could allow an unauthenticated, remote attacker to 
exploit this issue to cause the IoT-FND to stop responding.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-http2-reset-d8Kf32vZ
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?beb8acae");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwh88604");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwh88604");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-44487");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/12/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:iot_field_network_director");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("iot_field_network_director_webui_detect.nbin");
  script_require_keys("Cisco/IoT Field Network Director/Version");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'IoT Field Network Director');

var vuln_ranges = [
  {'min_ver': '0.0', 'fix_ver': '4.11.0'}
];

var reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCwh88604'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
