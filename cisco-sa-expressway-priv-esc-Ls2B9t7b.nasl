#TRUSTED 1a6b922f248f80e26ea59b9ccbf0e3d7b412e9add10e00067049f688700e1c0e5bb1d619941dfb9ddc9919cfd0896034221107d0486cc5e0c660c93d632c43c4caab10762ce642011ca55d611f9453f4bfbabe6e7e3929024bdff79dc7c211dc7e4507b43c3f467379633ad67e032a1776bf13a8037b548475526aa1d59ae51f1345182ad3355453ab86eb25704b579e5860236995218611d8d8fe6b5831078f8621d661e72c3d3ead5e92c58878f4abe50b6ff6b167ebf5905abca6ab40002b306a7d3a4781a25403527a35688996615cc4e9e539f891b77831497ee4b27c1ff3a140771ca7ef674d0504d5ed65c5215a02b49a4a9164075631f780fdc0f0c55bf58490c44e566264d13fa7907c8f9a847459b694ee5aab9c95c771bf2c7ca3ef651fc1158aa9d050fe655ec1155540f22b8252801317e3732d7d42443e3563d269f798c84097cf795bea18eb90e979714c37189aab9d884397610064c1b7ca5e66d3aa6a08e2d7aa22f77a22aa10f77ad4794be73a373e300e3d35365aae4dcddfa16109335f4cc51ed3b02cf4239b2208b84f486abea11f56cc1d820e77fae0676dc2928d782aa0a04a6fc5cdf4e8d5cb5adf8e0b1fcd7bc469e7e9b0ab8d874e1b2a3a68908df66fa1eda6373f3176791577a65bb2ac348a69314ac2fe86fb0ca32e3d922a4bba33d13250ca12b22e7a169812e7d0059d35ed2c40a52bdf
#TRUST-RSA-SHA256 9ccd672061dd0e497b891d7f6b795d543919e3cdf9a21b12fc940fdb5f478f6c9a487577a3447bfcee1b413ac9139356124139d690a139f91fc6c9a05161bb9a0fb2ce9ef2763ba258300b81af8e5aec9d30f3f0b022e653cb25f74b4de6b4bbbe0f7e1c1cbdbf7c50076b7c08400f90bbd52c73d1b2a0f5c1ed28b2990373299ec18f045e14b7f75a48353ce1851a8f39c9a9ff17d02b24d959fe229c07cd5cbb66a4f35ab58eb3179abdc9491233cd64decb9df433a1081fcd9bf1ba280f2f2f06a61ca07ab5358674aba4a67a1c8671dff6b7c36370c49928e8a9e1a9fe5867d61f5bbb074325d271119cf2e41c007f63833512808194c88ebcd97a9d506f5400f06c43001ddaa17683facf34cec3401400b9d5955692f9715211736f533f89f6a0b5bbdf85a06797ec3e12622e78aad016cf527e579cc747b86911d63a92c51806cd699df73ab5f0dabdf34fd6ee898060ee16baeaa81dc581641f458dd8ca289862190065925f837f1d370b0b58bb844770caf083aeb0aaf02cc6228500bc588a6afc8ced3ad30f6279c05715f1a55f1490edcc2ebc61c2d4215690f91c56238984580121a7ba18d6de970d2395d570e92dc776848b2ddc2f72b87d694d5790bebe1f96d7ba6b1b2eb83a162191eb5ba1c2044dfa8ad963b56966fe99ce99089c4d388b4b96038b785a6e1ea4fa57d936b17f9cda961dc5ed8215ef01cd
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(177367);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/08/24");

  script_cve_id("CVE-2023-20105");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvz54058");
  script_xref(name:"CISCO-SA", value:"cisco-sa-expressway-priv-esc-Ls2B9t7b");
  script_xref(name:"IAVA", value:"2023-A-0282-S");

  script_name(english:"Cisco Expressway Series / Cisco TelePresence VCS < 14.2.1 Privilege Escalation (cisco-sa-expressway-priv-esc-Ls2B9t7b)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The Cisco Expressway Series or Cisco TelePresence Video Communication Server (VCS) running on the remote host is
prior to 14.2.1. It is, therefore, affected by a privilege escalation vulnerability as described in the
cisco-sa-expressway-priv-esc-Ls2B9t7b advisory. Due to incorrect handling of password change requests, a remote
attacker with read-only administrator privileges can alter the passwords of any user on the system, including those
with administrator read-write access.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-expressway-priv-esc-Ls2B9t7b
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0b350287");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvz54058");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvz54058");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20105");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/06/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:telepresence_video_communication_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:telepresence_video_communication_server_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_telepresence_video_communication_server_detect.nbin");
  script_require_keys("Cisco/TelePresence_VCS/Version");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco TelePresence VCS');

var vuln_ranges = [{ 'min_ver':'0.0', 'fix_ver' : '14.2.1' }];

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_WARNING,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCvz54058',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
