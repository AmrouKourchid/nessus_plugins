#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(190360);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/12");

  script_cve_id("CVE-2021-36367");

  script_name(english:"PuTTY < 0.76 Insufficient Verification of Data Authenticity");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an SSH client that is affected by an insufficient verification
of data authenticity vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host has a version of PuTTY installed that is prior to 0.76, which proceeds with establishing
an SSH session even if it has never sent a substantive authentication response. This makes it easier for 
an attacker-controlled SSH server to present a later spoofed authentication prompt (that the attacker can 
use to capture credential data, and use that data for purposes that are undesired by the client user).
From version 0.76, PuTTY will include an option to abandon an SSH connection if the SSH server ends the user
authentication phase of the protocol without requiring any substantive input from PuTTY.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported 
version number.");
  # https://www.chiark.greenend.org.uk/~sgtatham/putty/wishlist/reject-trivial-auth.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a91dcb5c");
  # http://www.chiark.greenend.org.uk/~sgtatham/putty/changes.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9abf77e1");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PuTTY version 0.76 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-36367");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:simon_tatham:putty");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("putty_installed.nasl");
  script_require_keys("installed_sw/PuTTY", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit("SMB/Registry/Enumerated");

var app_info = vcf::get_app_info(app:"PuTTY", win_local:TRUE);

var constraints = [
  { "fixed_version" : "0.76" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
