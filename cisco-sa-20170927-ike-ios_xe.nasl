#TRUSTED 1236b9f38ac0ca1c4b5bf7659d09f40ecb473869a8481ede1242e4d57a0bd9528f2fc3948e95ad84e601094426b0810bb4b948a391ee9efe744d9476d68c1214fa6621834b704d34f1f3289cc30b986790e46000a0f989714f6add3fb29bafb4aeb3a844b687890214a25ee70b2f77ad3ab6f53bbc0223deb96cbcb0e5362b8bc735848607b06478ce3b3d1d1c8b06f103fdb89d53361e5e71fd372db30f825279060cb261a876088af42043986c8893973052a72b021ac9b82f8733554f429b5903898f0b8c4fedbd4a2c99eb2c4be2e789bf9b3c626f76b172d89ffd1985be387dc153c7e4c083becc1b3d870ce3b9582b5f7b1c4e17d122feafebc8c6917ef0fccec91c9b0786fdea9cf4be77a1f92f84298604f23a74ae8b0625d1aa573234cd8220ca13a7e30895de57bb47b604406c3f4e5b1ff916566d17fd2e6f81b1890a63600843eef013e2b772fd1cf5ad9e8556df212e63a7d00bfec7e9fd00176343c2c72d14f900d9c5cd0108d0fecf5177e2b473f87085db9a72986a112045d66e1ebeb9b3ff6057d748923c831c0c4f9b241c469cbb66cd0890b35d599ad9d7df12d564d3529fac8e629583105a8b51f18084fcdd51b9f74d85dc8c5749cef16590c9e5a2cf8d6dbd63e3e79224f87bcac3a52ff5de23ea3c67ac94d4b6375670451615de2459daad023dc7f26f9adb688ae8e24b4c65f804ecf17ef248a9
#TRUST-RSA-SHA256 418bff5d3ae34086bbebedbf684c28b9976276ec3bcb860037488ed87fd9dbc23c0043387b36310925c3376a7cf15a05ae38ab56cb63cc0777d7ef7ec174a4e69ca22ced7c8840e14f2189a22444418cc2eb508544421106c41f004c20b4ffa8b5b73a2255609587b23ffe5f445d6d74185423baf8dc512ca370acdc7b74e701d896b8b8404d049b388764d93e52051f0caa0df24114e2b92e89db4d93c386d45dc0dbd4f6d17a572b5535d837c0d0f62d97d1b7d275a419d8567f7adb6de3eee990b6a5856fe6254612876b50de99fd7bee62d281e3b805dd71aa3c6130f7ed8e6f961ca58e3eea935f9bb7ebe218f547ffa4b884b89aaff6f7609709ecb2231603cd6b3311b87f6ebdbc467f5d79c78d3b3c9a25fb6d86a63c4fa9f93bce11ea459f07aca0ba1b9a672e29e050f7f7d3711e80375f029446adf2671b8138ef3b5f72a098c842634b52a5fb300ee393ea87bf92fb2776a59ba90718cebb8e7a4832ef34caf3a4567f635468589bb2ae77df258400901d1b2082ad3fc797cfae5afd9c59cd5f8d4699732564487081ec7d841ea5f8f85040dbb2059007aa4fdf413cc28b305a25a5d29638140ad9b625154b729d527d3f35aca908193663a0f8c4236e482792bab86aecdeceb3d081c9ae84ae9864195a00063ac4222b0968e9e59f7b27e9f47532d1f741e60ae511487921c397dd8e22786fb32ba3485152ca
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(103694);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2017-12237");
  script_bugtraq_id(101037);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvc41277");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170927-ike");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/24");

  script_name(english:"Cisco IOS XE Software Internet Key Exchange Denial of Service Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS XE Software is affected
by one or more vulnerabilities. Please see the included Cisco BIDs
and the Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170927-ike
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2e9f54a3");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvc41277");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s)
CSCvc41277.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-12237");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/06");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_workarounds.inc");
include("ccf.inc");


product_info = cisco::get_product_info(name:"Cisco IOS XE Software");

version_list = make_list(
  "16.1.1",
  "16.1.2",
  "16.1.3",
  "16.1.3a",
  "16.1.4",
  "16.2.1",
  "16.2.2",
  "16.2.2a",
  "16.2.3",
  "16.3.1",
  "16.3.1a",
  "16.3.2",
  "16.3.3",
  "16.3.4",
  "16.4.1",
  "16.4.2",
  "16.5.1",
  "16.5.1a",
  "16.5.1b",
  "16.5.1c",
  "3.10.0S",
  "3.10.1S",
  "3.10.1xbS",
  "3.10.2S",
  "3.10.2tS",
  "3.10.3S",
  "3.10.4S",
  "3.10.5S",
  "3.10.6S",
  "3.10.7S",
  "3.10.8S",
  "3.10.8aS",
  "3.10.9S",
  "3.11.0S",
  "3.11.1S",
  "3.11.2S",
  "3.11.3S",
  "3.11.4S",
  "3.12.0S",
  "3.12.0aS",
  "3.12.1S",
  "3.12.2S",
  "3.12.3S",
  "3.12.4S",
  "3.13.0S",
  "3.13.0aS",
  "3.13.1S",
  "3.13.2S",
  "3.13.2aS",
  "3.13.3S",
  "3.13.4S",
  "3.13.5S",
  "3.13.5aS",
  "3.13.6S",
  "3.13.6aS",
  "3.13.7S",
  "3.13.7aS",
  "3.14.0S",
  "3.14.1S",
  "3.14.2S",
  "3.14.3S",
  "3.14.4S",
  "3.15.0S",
  "3.15.1S",
  "3.15.1cS",
  "3.15.2S",
  "3.15.3S",
  "3.15.4S",
  "3.16.0S",
  "3.16.0cS",
  "3.16.1S",
  "3.16.1aS",
  "3.16.2S",
  "3.16.2aS",
  "3.16.2bS",
  "3.16.3S",
  "3.16.3aS",
  "3.16.4S",
  "3.16.4aS",
  "3.16.4bS",
  "3.16.4dS",
  "3.16.5S",
  "3.17.0S",
  "3.17.1S",
  "3.17.1aS",
  "3.17.3S",
  "3.18.0S",
  "3.18.0SP",
  "3.18.0aS",
  "3.18.1S",
  "3.18.1SP",
  "3.18.1aSP",
  "3.18.1bSP",
  "3.18.1cSP",
  "3.18.2S",
  "3.18.2SP",
  "3.18.2aSP",
  "3.18.3S",
  "3.18.3vS",
  "3.5.0E",
  "3.5.1E",
  "3.5.2E",
  "3.5.3E",
  "3.6.0E",
  "3.6.0S",
  "3.6.1E",
  "3.6.1S",
  "3.6.2E",
  "3.6.2S",
  "3.6.2aE",
  "3.6.3E",
  "3.6.4E",
  "3.6.5E",
  "3.6.5aE",
  "3.6.5bE",
  "3.6.6E",
  "3.7.0E",
  "3.7.0S",
  "3.7.0bS",
  "3.7.1E",
  "3.7.1S",
  "3.7.1aS",
  "3.7.2E",
  "3.7.2S",
  "3.7.2tS",
  "3.7.3E",
  "3.7.3S",
  "3.7.4E",
  "3.7.4S",
  "3.7.4aS",
  "3.7.5E",
  "3.7.5S",
  "3.7.6S",
  "3.7.7S",
  "3.8.0E",
  "3.8.0EX",
  "3.8.0S",
  "3.8.1E",
  "3.8.1S",
  "3.8.2E",
  "3.8.2S",
  "3.8.3E",
  "3.8.4E",
  "3.9.0E",
  "3.9.0S",
  "3.9.0aS",
  "3.9.1E",
  "3.9.1S",
  "3.9.1aS",
  "3.9.2E",
  "3.9.2S"
);

workarounds = make_list(CISCO_WORKAROUNDS['show_udp_ike'],CISCO_WORKAROUNDS['show_ip_sock_ike']);
workaround_params = {"check_queue_limit" : 1};


reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , "CSCvc41277",
  'cmds'     , make_list("show udp", "show ip sockets")
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list, router_only:TRUE);
