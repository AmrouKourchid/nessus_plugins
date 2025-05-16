#TRUSTED 3b992003ec331616441511cc7aeddb3aad2bd16c44264de6d24d59551202daa05dc3198b6742c9556f9f4e7d2cc471af3ea1bd4ae8ec64c14e85746287593374563db40ad0907605a91e120c5af8f55997173a5ee7efa52cf714d5f293221281fb62343cd3898282c45d2f3dab0276f97e1e688147542ff21dc59730b2bf2e75f278cd237a67fec66371a7c45a75082ce9a63f64f3fd2e88ea3bf1cdbae89070df5c8efc1e887b1071959f4017b7d6d363b17f7d6510672537984317588ce05c9fedcb998ce3e25378bb12fe1baf589c925b7b1f1681b2b4b320b25fbf896dc30d0e5e8392eaa29b18e090b92f7c8309f2cae5e406b71025d2ef3f4b7b9200522377537fc5672fca1d7fcc40cefc0d26bce62462f6445d89e0e87e6c9c1ea7f620fbc7dae2567c790204aef9bc8f224ee3b12b196b7f56bb183388abf762497d5aa21eb3b7434afc32001349c7b588ce2b7fe46f4a9d5d6290af04d8a033aaec66bd1e6ab6bca9cbb4a91926782cae7e019bea58c1f2d0b6ac98ec5fbcf6de8456e4fc86f37a3d927af4abf3b3782980cb38c19b4563abf6e89ebb5a02ae7b1f1fa5f9a8dafd310a1f488708e02c21d61811884d633b9a4b31c334fa3e7bd3a9b12f3bf035a29ed6671f3f5ad5239422d384e7074d6f2d8110f7300c4cffe71c3b0e3494307baa8825de7fbadc148794b381b804b4f7db94ebea093c0490b89a
#TRUST-RSA-SHA256 17e679a10620cc90e485962edd0b6dccc383b3031390871810ebf78ed8803e48d3d35627718f449ba03e2e6c7877a9d45c90aa47c7b0965f499734cf530396e69c8a41883530ff930c955fe6955858a8a04d1214370e7ae0950622434f8e3f9d3fb3c87f914b22aec03647fa187728d38ed1f7184943703f2d7088bc54af2977d3350ba3b99361baa43812e931386542ab574a8280c6b9b9785ebb38112498141688e8001edc3a11e4e372fa08a6144a1b8217c9a1ab9543344211d3ec8c112a5edbd6b184f4794a750fda8c6254986fefb3c2e0fdb9f45e3b1ee9c82b5df3d53c2120d6dc986ea765e3da81bae9680a9769ae2f2e031159846b30f488bec07a0d68153ce79c8dd50834052cc5b0c60617d673bf3dfb01f7773474d68dc9faf95f76cbda2febf859d1a224b8cdfa3d346b63a8b95fce710f5fd7e17f314811c0ce4cf386fa8e382a397ac6792a66c1fcba612b9ba7b347f67d17c7a353efeea17cbd37db21e9dcf25751a798b6e8e7bc8cbc34f10c1caf5619cfeabeb7438b16fc7f3056420a9dd0f59f5514cef2f3f913968c691f3e630a404cee66c9faa381deefea7a14af1ea525560c0e0c1c3d4b431f459a9c687a683b1ab2bc8b1c72d7cd87ea98c2afd1d85b3e07dbb15ccf309c96d48b66ff21d308add11a4fb2b45425fbba6c5da9bfa96bf62e0b8df5d1dff2a8de7e4225e8aaf2c10467dacc87e2
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(131327);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2017-12226");
  script_bugtraq_id(101063);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvd73746");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170927-ngwc");

  script_name(english:"Cisco IOS XE Software, Catalyst, and NGWC GUI Privilege Escalation (cisco-sa-20170927-ngwc)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a privilege escalation vulnerability in
the web-based Wireless Controller GUI for Cisco 5760 Wireless LAN Controllers, Cisco Catalyst 4500E Supervisor Engine
8-E (Wireless) Switches, and Cisco New Generation Wireless Controllers (NGWC) 3850. This is due to incomplete input
validation of HTTP requests by the affected GUI, if the GUI connection state or protocol changes. An authenticated,
remote attacker can exploit this by authenticating with the Wireless Controller GUI as a Lobby Administrator user of an
affected device and then changing the state or protocol for their connection to the GUI. Successful exploitation of this
vulnerability would allow an attacker to elevate their privilege level to administrator to gain full control of the
affected device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170927-ngwc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?28a05a9f");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvd73746");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s) CSCvd73746.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-12226");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/27");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/IOS-XE/Model");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');
model = get_kb_item_or_exit('Host/Cisco/IOS-XE/Model');
device_model = get_kb_item("Host/Cisco/device_model");

# Affected models:
# Cisco Catalyst 4500E Supervisor Engine 8-E (Wireless) Switches
# Cisco 5760 Wireless LAN Controllers
# Cisco New Generation Wireless Controllers (NGWC) 3850
vuln = FALSE;
show_ver = get_kb_item("Host/Cisco/show_ver");
if (device_model =~ "cat" &&
    ((product_info.model =~ "([^0-9]|^)45[0-9]{2}E" && "WS-X45-SUP8-E" >< show_ver) ||
    product_info.model =~ "([^0-9]|^)38[0-9]{2}")
   )
  vuln = TRUE;
# In advisory example, 5760 has 5700 so just look for 57xx. 
# On Software Downloads page, 5760 is the only 5700 Series WLC
else if (product_info.model =~ "([^0-9]|^)57[0-9]{2} Series Wireless LAN Controller")
  vuln = TRUE;

if (!vuln)
  audit(AUDIT_HOST_NOT, "affected");

version_list = make_list(
  '3.7.0E',
  '3.7.1E',
  '3.7.2E',
  '3.7.3E',
  '3.7.4E',
  '3.7.5E'
);

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvd73746'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list,
  workarounds:workarounds,
  workaround_params:workaround_params
);
