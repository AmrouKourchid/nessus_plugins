#TRUSTED 6631c644786f056ed50903d51dcf26d20bdf6545db22b741ca586b67f82b771059bbb619a24ca1207e19e4baa3a4db4d8a5410db55f72fa03b9d1e41939d5ce0d6eb895b0a3383b2ddd8038c4d0426e1ff76a2a563f96b38bdf5aea2ae9148adfa919e76af97e12248a31a4b027c46334c27b128063f2772eca6abc42deea759dbc5fb54bda864f93138994b0471a8ad7f4157eef2ab0b59e0bc3c2fc86d947a9913b334a0ba14f44373ade061cd135b5c2afba12927321f4588ed2ee8b2be91229c39dcc9151a1d5b173cb317816f5e98a5b34ab9b15d52ab7a313ad4bc1d68bdc0f1931fb8c033f0a2285e0fd33849efe5ab720f2424509971730959258b26afd1b79c801e90958f0af363adbe29afbc2ec1b6c12ba45bdfeade750c6a6ddf7f22fee53d7d6c7bb1eb54b1f5a5a4bee787412da99cc5cd820ff2f019a9fc89b020eed839a226f5939d4e168c67d8d90d1c35be3416a101b27f71b34f746933dcb345314d7bb3d93c51b4a542f411c633335f9dd4ee6f7f7a35e88f0c72219b175646f075bfab76a39e372296c9262941bce2125a569c0a6c027b31c22556ef4fd5f0c680641a23632c92a0c5d73102fd7523bd1f835b20627b26d1a39b6d4d7bb378f1f69bd672fac324ddc6f9a4bfae5426368a33392816a7a6bf3e41f678231f43e868947e2d96e07f33423a12cdab71ba4586b5f5e58027c2461ab244a1
#TRUST-RSA-SHA256 6872b481355c26c754862393572f3d19dbf4b65a6fcb95347b1bab72818e2d7778e13b4fddf338d9a6e6ca21665cda4fb6e00d93bc8d9823a4c969fbf82d1777efe4aca04f06904b3698018d7c7a496e5058c9177e57fba3484e73031e1ae24f982afff5adc7cd5370e5c53c5549ad348a45c4a7cbfa80ed8022086a9cc89169a32f6e3d86b9b480ae4d6b8221b72c0845b4dbac56e700a99d8719108ad2e8e8ed81372ef5e0bc7c2a8f5b68c44f58062591cb0340ec69b20ab410068a7bf1c33e05a3c5da6aae6534181cfe52127e075b469567ac1cb50c5fb0ce254a9a16f09af6606debd02924d2dafa64ea4fa718f0651e0104611d58b0795cc43304a773a8977a6543fbc04fd7955a2b85e8bebb63698c028afabed417c35104996cd48b54b4401be47f1918ac670088ffe0e382701269327c3a881ad95cb9747dcc2c7788bbfe57aab135af81920ce0353b468d3a58efd3c042fe27acb1240bc869aab5616ea9c2f31b971e3f7b16ef39cb1fa47ad29297709dde71d16c774f1fa35d4c5d4b0e5f2befbd781425926c2d7547154173a461ffc41f3cebed0a4d472e3aaa4951b21400b7bbe13014840365ebc3a20adf61544204b38e119d55f282c6b8fb694d0930890b8549c1666f5e97f53760508865e926389b367c88e56bbacdd674396bc4270157b6ae4b878351c3aced9d355ee510f24276a26f9c186678811a10
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99688);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id(
    "CVE-2017-3860",
    "CVE-2017-3861",
    "CVE-2017-3862",
    "CVE-2017-3863"
  );
  script_bugtraq_id(97935);
  script_xref(name:"CISCO-BUG-ID", value:"CSCur29331");
  script_xref(name:"CISCO-BUG-ID", value:"CSCut47751");
  script_xref(name:"CISCO-BUG-ID", value:"CSCut50727");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuu76493");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170419-energywise");

  script_name(english:"Cisco IOS XE EnergyWise DoS (cisco-sa-20170419-energywise)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS XE software
running on the remote device is affected by multiple buffer overflow
conditions due to improper parsing of EnergyWise packets. An
unauthenticated, remote attacker can exploit these, by sending
specially crafted IPv4 EnergyWise packets to the device, to cause a
denial of service condition. Note that IPv6 packets cannot be used to
exploit these issues and that the EnergyWise feature is not enabled by
default on Cisco XE devices.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170419-energywise
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7d2ebdad");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCur29331");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCut47751");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCut50727");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuu76493");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco Security
Advisory cisco-sa-20170419-energywise.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-3860");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/26");

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
  "3.2.0SG",
  "3.2.1SG",
  "3.2.2SG",
  "3.2.3SG",
  "3.2.4SG",
  "3.2.5SG",
  "3.2.6SG",
  "3.2.7SG",
  "3.2.8SG",
  "3.2.9SG",
  "3.2.10SG",
  "3.2.11SG",
  "3.7.7S",
  "3.2.0XO",
  "3.3.0SG",
  "3.3.2SG",
  "3.3.1SG",
  "3.3.0XO",
  "3.3.1XO",
  "3.3.2XO",
  "3.4.0SG",
  "3.4.2SG",
  "3.4.1SG",
  "3.4.3SG",
  "3.4.4SG",
  "3.4.5SG",
  "3.4.6SG",
  "3.4.7SG",
  "3.4.8SG",
  "3.5.0E",
  "3.5.1E",
  "3.5.2E",
  "3.5.3E",
  "3.10.4S",
  "3.10.8aS",
  "3.10.9S",
  "3.12.0aS",
  "3.6.0E",
  "3.6.1E",
  "3.6.0aE",
  "3.6.0bE",
  "3.6.2aE",
  "3.6.2E",
  "3.6.3E",
  "3.6.4E",
  "3.6.5E",
  "3.6.6E",
  "3.6.5aE",
  "3.6.5bE",
  "3.15.2xbS",
  "3.15.4S",
  "3.3.0SQ",
  "3.3.1SQ",
  "3.4.0SQ",
  "3.4.1SQ",
  "3.7.0E",
  "3.7.1E",
  "3.7.2E",
  "3.7.3E",
  "3.5.0SQ",
  "3.5.1SQ",
  "3.5.2SQ",
  "3.5.3SQ",
  "3.5.4SQ",
  "3.5.5SQ",
  "3.5.6SQ",
  "3.5.7SQ",
  "3.5.8SQ",
  "3.16.1S",
  "3.16.0bS",
  "16.1.1",
  "16.1.2",
  "16.1.3",
  "16.2.1",
  "16.2.2",
  "3.8.0E",
  "3.18.3vS",
  "3.18.3bSP",
  "16.7.1b",
  "16.10.1",
  "16.11.1",
  "16.12.1",
  "16.13.1",
  "16.14.1",
  "16.15.1");

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['energywise'];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , "CSCur29331, CSCut47751, CSCut50727, and CSCuu76493",
  'cmds'     , make_list("show running-config")
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
