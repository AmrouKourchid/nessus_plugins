#TRUSTED 2eaba2333e13a1b98e7f69c2a44b58f3e26fe582889770986c7c5a93d200d53b83c908f76ae7f19339988712a20b0383c141b3f16a2f26e9ab9e11dce221951c282dc76ff7c5d460f2c19d64ff222f9bd60ef7eb43de67e3661f424d2471ed541060c5f2a4c055e7cedbeafaa3374f0e93e1727f37316874151f615896412bbed753c80f11320049234a051a40448658fac39525da1fbb52124aef818d9352cd235cca5f494f2e5534b6b45cfdc419af4f080e55fc669ff070d873b54fdbd5ea5f5c06d4616b65bc99108cc6ff987a591e0dbbf43783369cc17531fab65bac0fcc860069ae006811f40ff8f47b482fb800a26c28dec28abfe6fe3a6ce6dfb44c7d970faa4ca5b012d0b38889238317c56707dcad4465a0de6417c4b0879bcf3a553618b67f5bbdc4cc6b9dffd0afa9049fd4a2635c8156d8f81004ddeb1434b4f826eafdc0c14203f06f4ac7da8336d89f0c62c5cba9a965201e1fcb4fd8cbc01ec78c1d723a61c258f68cb1ebf3d3043962149dd5f3c2acd81c61a96b110a51957e8541e34228c7e9c4674c493c3cc9ee7e39d2ccc147e8c87851920a14d892b3efdb8c6d88e2af894109f51954c2d677b83f1ea850f809086b78e17c27c0824a7705e9d44c26169dcfe0d223b8b0b63dc2cde76e333b192ccda9784fd834cb84e689ca860697227c6a099c65655551fc3c02464e19647f5881a27f8740ab5c
#TRUST-RSA-SHA256 8df21c2ed2eb6286413ca3fa0871fc358837ccc71a4b5899619669a6e42a28286a027c101a0bb2fa085d1daa92fb72d8d5f8f2ca6b6f264c16133d64f641aefc46bbcd3f3452382369498f4391d2cc9fc8389b0a7360c7b4cab63d38de9effa90d7052f03142ba7b568dc2585d9c3e31d743cd73ce48bd8d133bcad64a940cbad47bc642e32cca186e713263a0fd72302074330e35818954330b2015b3c7e03cd7e4360ff586bed832ad4eb13d669586d97125fac1b10594626cede57e06e053317d0608409effc9e9242bd02bdae888677ab39bc5d2299cd49c85ccf6a509b15c26416402b2c56e34bcc968a86794021c30bb103c7b3332228a47a1fc2c71dfc5c336fe57236e83f45672dfa43b18770c6942cdce4e03b6255e2b45175594c72970af0e307c54c4f15a2074c88b058c13d7b26fcb1a34bc2f889fac215220235bdb94dbf2720f25f794ade667011a51f26f3345185907bc2bc8096145f1a7cc52c24dde70ae3516c455158a9d0bc0a35576bf6c0c8f6d297761d9499465ed083609a1c10379fb447454b5f21834beb805bfa9090d3751e3ee863e3bc74e4c4544a7c428baa4dd6a622cb696229240fd03c221197c6dc94959c90a12a4a49f7ee1a891c0779ad50239e0524fd0c138ecf5d0561f2d87047656ff47f6717f0c87928f40c037e89a96bc9478a653567f3d5f2c6c13856248c5d2dab16ae22e883f
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97946);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/18");

  script_cve_id("CVE-2017-3850");
  script_bugtraq_id(96971);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvc42729");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170320-aniipv6");

  script_name(english:"Cisco IOS XE ANI IPv6 Packets DoS (cisco-sa-20170320-aniipv6)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS XE software
running on the remote device is affected by a denial of service
vulnerability in the Autonomic Networking Infrastructure (ANI)
component due to incomplete input validation of certain crafted IPv6
packets. An unauthenticated, remote attacker can exploit this issue,
via specially crafted IPv6 packets, to cause the device to reload.

Note that this issue only affect devices with ANI enabled that have a
reachable IPv6 interface.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170320-aniipv6
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8d249229");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20170320-aniipv6.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-3850");
  script_set_attribute(attribute: "cvss3_score_source", value: "manual");
  script_set_attribute(attribute:"cvss3_score_rationale", value:"Scoring adjustsed to align with CVSS 3.1 attack complexity guidance.");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/24");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_workarounds.inc");
include("ccf.inc");

product_info = cisco::get_product_info(name:"Cisco IOS XE Software");

version_list = make_list(
  '3.10.0S',
  '3.10.1S',
  '3.10.2S',
  '3.10.3S',
  '3.10.4S',
  '3.10.5S',
  '3.10.6S',
  '3.10.7S',
  '3.10.1xbS',
  '3.10.8S',
  '3.11.1S',
  '3.11.2S',
  '3.11.0S',
  '3.11.3S',
  '3.11.4S',
  '3.12.1S',
  '3.12.2S',
  '3.12.3S',
  '3.12.0aS',
  '3.12.4S',
  '3.13.0S',
  '3.13.1S',
  '3.13.2S',
  '3.13.3S',
  '3.13.4S',
  '3.13.5S',
  '3.13.0aS',
  '3.13.5aS',
  '3.13.6S',
  '3.13.6aS',
  '3.14.0S',
  '3.14.1S',
  '3.14.2S',
  '3.14.3S',
  '3.14.4S',
  '3.15.0S',
  '3.15.1S',
  '3.15.2S',
  '3.15.1cS',
  '3.15.3S',
  '3.15.4S',
  '3.7.0E',
  '3.7.1E',
  '3.7.2E',
  '3.7.3E',
  '3.7.4E',
  '3.7.5E',
  '3.16.0S',
  '3.16.1S',
  '3.16.1aS',
  '3.16.2S',
  '3.16.2aS',
  '3.16.0cS',
  '3.16.3S',
  '3.16.2bS',
  '3.16.3aS',
  '3.16.4S',
  '3.16.4aS',
  '3.16.4bS',
  '3.16.5S',
  '3.16.4dS',
  '3.17.0S',
  '3.17.1S',
  '3.17.2S ',
  '3.17.1aS',
  '3.17.3S',
  '3.8.0E',
  '3.8.1E',
  '3.8.2E',
  '3.8.3E',
  '3.18.0aS',
  '3.18.0S',
  '3.18.1S',
  '3.18.2S',
  '3.18.3vS',
  '3.18.0SP',
  '3.18.1SP',
  '3.18.1aSP',
  '3.18.1bSP',
  '3.9.0E',
  '3.9.1E'
  );

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['ipv6_enabled'];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , "CSCvc42729",
  'cmds'     , make_list("show running-config")
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
