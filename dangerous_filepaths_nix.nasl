#TRUSTED 62df0a8367be8f8e16e67a8cd2d75de40b56b0d8cbc76c85d97f034184fe585497cdba6a81642e58faee4f534e18845e857ffd45714f46c69d14bf868daca174e8c1f8bc2eac731cd578e9e67d76410ba62750eacf95b17aad063bf8f86526ab475e4f9c6fbf1380fd167c125b836277b3f25953c4b948ecb6d99581a4b6c43b647f07c65a25400ba012b9ea1a9c918e313dc2324269050fb8246084e9ad5e5ba43a08ae36ada626dbcd425433d501c239a9ffc0ab2e093341eaab30a2035ee16cd05a8a76b8adaf35f2009168e7f8d99d7cb2a9cabd5f06620b6f73770868fe61d408de13c9e4ff1f266a3d460a1b735181c793c8a784dd91be61b50f916c1275d340c9c5280e07145c1f0f3510eaba6d5b773f349ab0e063d6d707bf10d5c6906b1d9a1858002f7e4f08c152a0bd551a6880ddf87cbfa57de413a0fba032877235a4b3bbc26b889486e843f522c4e6167be6d077467fa73acf55fb0bdb9a135212853959d60e9ad9a1def489a613fcadb402dfa83c0793fc060615d9476d5db7bac05d3d2672b9078fb7c3b6b52e383e3b023238186ce96850750191d0e2e71fccbed240d9de9b7691c5b8642ea1aef18497ac06b47f75d136c0d7d1b8806be6a1578a8fb624493583ac8f32f100ec27cdecdf4891fe4cd486e5e087086c57cb6d48c8112c074ad63466699d58bc10ac9ef64a45b11f1378be4194df28b3d0
#TRUST-RSA-SHA256 624a04d6ef05ac8ed9504b74dd197c26a3f6b502785bf46bdd6ce631b82912894e5a38b01c04f0b3b6fe674289393ba23aac8fe9b4bb2b3d0a318b9319b945df59c89aca41ddb243fce696655badaf2c8b946af26f433b2d57f386eb6053ee17429c2da71c7230ef4f17458a56695f83c99ac6671c2b9600e2957d4dc714632a77b2b3c18d3f6cd0b9d427895877809926f9717152f341b071b6bea8d36b9fc57f0592f312645baa86c912b8fc697b4be5ab503272fa85fa0b17b125d4243416fe365fe281da1691135c37dba0bce51f68c9f472891ea1ab1a97481fa585c7ddba25b77964b8c8fd023fe2ff1f954dcad8d99cb7bf154569f1ab428e8b806e6933ac19719edc7d7ce6c60e8dc4cc0a8765dbf64bca18b0021f36c8cd71c10cad9ce4c0a08d7c4e89380382fd05646a382293045799dea6012d7751e19929ed2c8389f3cc2bfe29db040af5e8153a0ca96581c62687faebeca609afb3a478d87e22095187b29d6c1880039f03c07fdac0e714d72e52d5d9ab85643033d69560f0117dd611849b521e62fda3e18df296d565ba5dc26e503cc970e6ad019c11b5fdbd09b118b1b6762be4d3176c0774e2d7fbabccbfd741a31cfb6ce5d47b0a9d6d96b597670a32f5bcdb03f71cbe7877c070f20d11a1ce63eceb3bf735f90fae84af206247f15bf706e320968a3828069b96188ada6d2f9173c1065a8acf625dd5
#%NASL_MIN_LEVEL 80900
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(168982);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/24");

  script_name(english:"Filepaths contain Dangerous characters (Linux)");
  script_summary(english:"Reports filepaths with dangerous characters.");

  script_set_attribute(attribute:"synopsis", value:
"This Tenable product detected files or paths on the scanned Unix-like system which contain characters with command
injection or privilege escalation potential.");
  script_set_attribute(attribute:"description", value:
"This Tenable product detected files or paths on the scanned Unix-like system which contain characters with command
injection or privilege escalation potential. Although almost any character is valid for an entry in this kind of
filesystem, such as semicolons, use of some of them may lead to problems or security compromise when used in further
commands.

This product has chosen in certain plugins to avoid digging within those files and directories for security reasons.
These should be renamed to avoid security compromise.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/21");
  script_set_attribute(attribute:"solution", value:"Rename these files or folders to not include dangerous characters.");
  script_set_attribute(attribute:"plugin_type", value:"summary");
  script_end_attributes();

  script_category(ACT_END);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_require_keys('Host/Linux/dangerous_filepaths_found');
  exit(0);
}

include("ssh_lib.inc");
include("lcx.inc");

# We call this in case we rewrote it for testing purposes
lcx::check_localhost();

get_kb_item_or_exit('Host/Linux/dangerous_filepaths_found');

var res = query_scratchpad("SELECT DISTINCT path FROM nix_dangerous_filepaths ORDER BY path ASC");

if (empty_or_null(res))
{
  exit(0, "No dangerous linux filespaths were found.");
}

var report =
  'The following files and directories contain potentially dangerous characters such as brackets, ampersand, or semicolon.\n' +
  'This scanner avoided access to these files when possible for safety:\n';

var headerlength = strlen(report);

foreach var entry (res)
{
  entry = entry['path'];
  report += '\n' + entry;
}

if (strlen(report) == headerlength)
{
  # This should never happen, something really went wrong if the entries didn't write to the array correctly
  # Check anyway, reporting by default without this check would be unacceptable.
  exit(1, "Error reading dangerous windows filepath entries.");
}
security_report_v4(port:sshlib::kb_ssh_transport(), extra:report, severity:SECURITY_NOTE);
