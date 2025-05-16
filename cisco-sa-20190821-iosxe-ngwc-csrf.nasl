#TRUSTED 46aff25b20c68b1e41c6ec91cd1330a4eb39396f47d40a84cbca176edbe2935ed8c8efb8caa62684c8b19e5e260554e784d25b24f8294769b6462eac9385f4146e135163ba2138e4338726a906975e24b4164267e120671eaacef288a9b1428ed1e47213020bc7f3cf35fe3ddcd12edee50340acb6d6286795066e91e4b6a13d585180155cfc2fa4c4583b384037df98b9557703a5ea4385880abfa19053844833256ae909a18aefd23081772dc60ca172a608b79b8142170a1b5df15072d786357a0bea0b7a43ef3ad9d79d6efa15b793ef75f0e6f94f41c3f8ffe9773a2e230340972ac7b7ddfa7638a42db1b1156b9f8628f721c59663a9d7fff33f2cdbd1deef7ad3b2a4b13973f4f66d4f13b89e78622514ed3b8e38a7142a0f0533b0709cb91ba564127d5c0bb905f2eeb6131467070a2304a28b68e7f95dec3420a842a4358e7d0d5dacc4002b388553b1c980f6bf6dfe8f98aef1ea86a463e4cda82fea84669fb35d2db4cd2b58b1cf59ceaff9da53577d776be848a5a7cf107fa6c033a053e4452ce008e4a186d17a283acc80bb4c80d2886bddffd93ef4941031c80626860b6e9a39f6882d1911811b8c06a2b222362b2159d971acaea1ea3cb3b664835abf0353e414a6acb00b53f5070114f66dbf4c60469802cf5c48a596a1edeebccf24c73e0b7aa20a67bd9871f16aeb5c8dc4e6e7e2eb60d0ae8cbc603b4a
#TRUST-RSA-SHA256 b301c925db77db3c013612bde6588b8ccd589dca6660246c93bef049143fe81717e4fa44e5bc1e8140a51ce203c7341131d916159971c5bca2f4b9a056b184f1fe367d9e4764fe386b5bda0d339729bf6276f97ba73009770dda38646797d69521d5c0eb53bb3e18e74ce48fcab9ae5a347f7296fefa28d1f8ce0891697fa355becbc5cf353ea33e9b94a74e2b51ad49e4d3775d1f29aa6c935f6c071a4308dbc025f1ae457f32af25964be24cbd744c94b945892553bc769cf7553b7a5ad7b5b1d4de32b6b4a4b362621f429e99863d04f7a2cf0a40e9a1ab5b710ae30c32d780d8fdcefe77d379c2c9d42b2feea121b25149ab04de384ffcf9ba3d4b5000cf95bfd9739d29ed3dbb795873296f9a80aefdb0fe4f2ce64c3a9ace83e02a13bc274a958c1d23b3297b7e1e27c0532c1d6eae880e8e28c1b94a4365655dfc39a4ed3c5027dccdce6a470e1f1e2539773c9e074262a2cad92ff81d182fddb2d5b8653aad05df3d505521e017cfd84c790e5d5b335ec601720aa52e967840f4166a145f603adcfaa45a99191bbbe113266812a5eca7baea157caf4b071074997f716a52515815813f28ba946a2fda5146424c1f8bb65a4b45f394f061814ee4c589cb22ee868522ff649d88e64299d87aaf08c8bc624e9b0278decaba898fe5c6e8127dfb0b965a3744c7e491bc9ac78a2a4d23e85bc2dcccb9b1db0556cd8aadb5
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(131427);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2019-12624");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq64435");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190821-iosxe-ngwc-csrf");
  script_xref(name:"IAVA", value:"2019-A-0316-S");

  script_name(english:"Cisco IOS XE NGWC Legacy Wireless Device Manager GUI CSRF Vulnerability (cisco-sa-20190821-iosxe-ngwc-csrf)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a CSRF vulnerability");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a vulnerability in the web-based
management interface of Cisco IOS XE New Generation Wireless Controller (NGWC) which allow an unauthenticated, remote
attacker to conduct a cross-site request forgery (CSRF) attack and perform arbitrary actions on an affected device.
The vulnerability is due to insufficient CSRF protections for the web-based management interface of the affected
software. An attacker could exploit this vulnerability by persuading a user of the interface to follow a crafted link.
A successful exploit could allow the attacker to perform arbitrary actions on an affected device by using a web browser
and with the privileges of the user.

Please see the included Cisco BID(s) and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190821-iosxe-ngwc-csrf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8af6c2cc");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq64435");
  script_set_attribute(attribute:"solution", value:
"No fix available. Please refer to Cisco bug ID CSCvq64435");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12624");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(352);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/03");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Settings/ParanoidReport", "Host/Cisco/IOS-XE/Model");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');
model = get_kb_item_or_exit('Host/Cisco/IOS-XE/Model');
device_model = get_kb_item('Host/Cisco/device_model');

# Affected models:
# Cisco Catalyst 4500E Supervisor Engine 8-E (Wireless) Switches
# 5760 Wireless LAN Controllers
# Catalyst 3650 Series Switches
# Catalyst 3850 Series Switches
vuln = FALSE;
show_ver = get_kb_item("Host/Cisco/show_ver");
if (device_model =~ "cat" &&
    ((product_info.model =~ "([^0-9]|^)45[0-9]{2}E" && "WS-X45-SUP8-E" >< show_ver) ||
    product_info.model =~ "([^0-9]|^)3[68][0-9]{2}")
   )
  vuln = TRUE;
# In a previous advisory example (cisco-sa-20170927-ngwc), 5760 has 5700 so just look for 57xx.
# On Software Downloads page, 5760 is the only 5700 Series WLC
else if (product_info.model =~ "([^0-9]|^)57[0-9]{2} Series Wireless LAN Controller")
  vuln = TRUE;

if (!vuln || 'e' >!< tolower(product_info.version))
  audit(AUDIT_HOST_NOT, "affected");

vuln_ranges = [
  {'min_ver' : '3.0', 'fix_ver' : '4.0'}
];

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_WARNING,
  'version'  , product_info.version,
  'bug_id'   , 'CSCvq64435',
  'fix'      , 'No known fix, refer to Cisco advisory'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
