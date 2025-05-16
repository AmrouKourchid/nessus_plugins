#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(205312);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/12");

  script_cve_id("CVE-2024-31497");

  script_name(english:"WinSCP < 6.3.3 Key Recovery Attack Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"A file transfer application installed on the remote Windows host is affected by a key recovery attack vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of WinSCP installed on the remote Windows host is prior to 6.3.3. It is, therefore, affected by a key 
recovery attack vulnerability. In PuTTY 0.68 through 0.80 before 0.81, biased ECDSA nonce generation allows an attacker 
to recover a user's NIST P-521 secret key via a quick attack in approximately 60 signatures. This is especially 
important in a scenario where an adversary is able to read messages signed by PuTTY or Pageant. The required set of 
signed messages may be publicly readable because they are stored in a public Git service that supports use of SSH for 
commit signing, and the signatures were made by Pageant through an agent-forwarding mechanism. In other words, an 
adversary may already have enough signature information to compromise a victim's private key, even if there is no 
further use of vulnerable PuTTY versions. After a key compromise, an adversary may be able to conduct supply-chain 
attacks on software maintained in Git. A second, independent scenario is that the adversary is an operator of an SSH 
server to which the victim authenticates (for remote login or file copy), even though this server is not fully trusted 
by the victim, and the victim uses the same private key for SSH connections to other services operated by other 
entities. Here, the rogue server operator (who would otherwise have no way to determine the victim's private key) can 
derive the victim's private key, and then use it for unauthorized access to those other services. If the other services 
include Git services, then again it may be possible to conduct supply-chain attacks on software maintained in Git. 
This also affects, for example, FileZilla before 3.67.0, WinSCP before 6.3.3, TortoiseGit before 2.15.0.1, and 
TortoiseSVN through 1.14.6.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://thehackernews.com/2024/04/widely-used-putty-ssh-client-found.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0d963cbf");
  script_set_attribute(attribute:"solution", value:
"Upgrade to WinSCP version 6.3.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-31497");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:winscp:winscp");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("winscp_installed.nbin");
  script_require_keys("installed_sw/WinSCP");

  exit(0);
}

include('vcf.inc');
get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'WinSCP', win_local:TRUE);

var constraints = [
  {'fixed_version' : '6.3.3'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);