#TRUSTED 8ab3c76290415691c00456983dfc3cad47e353f72fb3a34fbe7597e8c8287a74815b463827563c790b6c0fb73d746c36135b0ba022f1daffd8c90f661bcafa4a84e6e65d54e0af0dd6b79fdbd60148c64f3b6b82857b5c70489d16b543c50e77c173781eb6172f2eaf236162a911fb1250cb5318eb1dd840a99557cfbbaf81c65f0a0c3a0030fcee8bcb814ceaeb8f120663163705cf7e3eb3a56f6727b7d263f6c02d9c8d0390c1858b711ba83fab0f69580c559cb0debd70bb5d83b1c8e6f89f26974768431c0a7d621753b927046f381d15792bb735dfe01b8d46d4320fe729cab582c2e38aa65cad0c042e3d58d2392beca162c85b54fe83a6544a1c73b9a66b0b531ab593b3add1acfa04eb5c85abd2eb30c1daa9213f18b429598261f4d11755a8edcc9f07cf35d41e9b437088a6e552d38647bed1532736ef29b54e47945efa9bed977d88bc81d229230ad50af73dd0f2a2dde6a8a189e160695bdb94ab2156d05a36dc710f4f97de7f652c9a96fdd8da72262fe771598fe09ae81ba4d4e3544f42d8f3f3f66b1bb826af548039e3e7e8805f540a73b94c8c806b6423c056ba219e35062a5815d13293e70a3d04f1befb0fdb5e3716b0f977099b6fe9304938cc228ec03cab180f491273979d0d3eb47a08fa95e29308b105ffb79003dc14151af1653b1edfb9ec33db6f3e8ed3aa1f8f4dd6279a0febc5c1763a2d5c
#TRUST-RSA-SHA256 9d5eba055d4c7db902c07d473df82bc8a5527319e7bd9a92ca928e9d1483e92ae69a49cb079d6eada7adf34fe4b4f9ee7510aeec84837a95aeba6658764d48a6f923521f51d222e530f4660f9a3c8ba762a6da0ff5f54ef6bebb51e044b3ddd5d6f49735edecd422fdb5a8fb59ecac50b6dfb133368d18fe2218eb12a08ecc450c22e6b075ae256d3f15ab1910e295287cce968d217c5a3c547029470472bff7e12df081550fdf90afbe3937d76f5c79b23709aee0cb5eb889540d2026253dd2525a0135a7bdeca45f2c42b56926696f3697386f72ab40287d95b1977184160d0a79618280fb450b0201f8893426ac4d9725de47a9034206edbb10a1a8eae9e5ed7a16756e9db4ce0246ebfc92d54a8049e5c8e9ea007653c2a22c8c5b9bde8dff2646e58437bf685a6920c915a3b5d980bf5765499fbea82e904796d6bcd49e2954f73d4961303fbe52fa602865690d8edc1dfcfafcda8b9cb77b50537c998883ae843d7ca33f7fed43f9c9859eaf2b9d4abba72af5b0790a1cec2e0492b63d26b9b4c87d188ddd7e6c7f00d2eb95693796a841773d3732fc389d3e33c75bf1ccfa42a1b10556e923f42274c68f7a86b87f3c2af8d29b9d984de484d152a53f49622e7ec0dec3349ae02ba29d6d5f4d28746769c3d3ab14de09c7a99ee692d702230bef0c1cd9dcb156cddb58c19d991cdd8a070ddcc6901ddc0fc7a13e395a
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(127099);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2019-1762");
  script_bugtraq_id(107594);
  script_xref(name:"IAVA", value:"2019-A-0264");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi66418");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190327-info");

  script_name(english:"Cisco IOS XE Software Information Disclosure Vulnerability (cisco-sa-20190327-info)");
  script_summary(english:"Checks the version of Cisco IOS XE Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is
affected by an unspecified vulnerability in the Secure Storage
feature of Cisco IOS XE that allows an authenticated, local attacker
to access sensitive system information on an affected device. The
vulnerability is due to improper memory operations performed at
encryption time, when affected software handles configuration
updates. An attacker can exploit this vulnerability by retrieving
the contents of specific memory locations of an affected device.
A successful exploit could result in the disclosure of keying
materials that are part of the device configuration, which can be
used to recover critical system information. (CVE-2019-1762)

Please see the included Cisco BID and Cisco Security Advisory for
more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190327-info
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?314cb57a");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi66418");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvi66418.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1762");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(200);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/29");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list = make_list(
  '16.6.1',
  '16.6.2',
  '16.6.3',
  '16.6.4',
  '16.6.4a',
  '16.6.4s',
  '16.7.1',
  '16.7.1a',
  '16.7.1b',
  '16.7.2',
  '16.7.3',
  '16.8.1',
  '16.8.1a',
  '16.8.1b',
  '16.8.1c',
  '16.8.1d',
  '16.8.1e',
  '16.8.1s',
  '16.8.2',
  '16.9.1',
  '16.9.1a',
  '16.9.1b',
  '16.9.1c',
  '16.9.1d',
  '16.9.1s',
  '16.9.2a'
);

workarounds = make_list(CISCO_WORKAROUNDS['service_private_config_encryption']);
workaround_params = make_list();

reporting = make_array(
'port'     , product_info['port'], 
'severity' , SECURITY_NOTE,
'version'  , product_info['version'],
'bug_id'   , 'CSCvi66418',
'cmds'     , make_list('show running-config all | include service private-config-encryption')
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
