#%NASL_MIN_LEVEL 80900
## 
# (C) Tenable, Inc.
#                                  
# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2025-26.
# The text itself is copyright (C) Mozilla Foundation.
##

include('compat.inc');

if (description)
{
  script_id(234491);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/05");

  script_cve_id("CVE-2025-2830", "CVE-2025-3522", "CVE-2025-3523");
  script_xref(name:"IAVA", value:"2025-A-0279-S");

  script_name(english:"Mozilla Thunderbird < 137.0.2");

  script_set_attribute(attribute:"synopsis", value:
"A mail client installed on the remote macOS or Mac OS X host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Thunderbird installed on the remote macOS or Mac OS X host is prior to 137.0.2. It is, therefore,
affected by multiple vulnerabilities as referenced in the mfsa2025-26 advisory.

  - Thunderbird processes the X-Mozilla-External-Attachment-URL header to handle attachments which can be
    hosted externally. When an email is opened, Thunderbird accesses the specified URL to  determine file
    size, and navigates to it when the user clicks the attachment. Because the URL is not validated or
    sanitized, it can reference internal resources like chrome:// or SMB share file:// links, potentially
    leading to hashed Windows credential leakage and opening the door to more serious security issues.
    (CVE-2025-3522)

  - By crafting a malformed file name for an attachment in a multipart message, an attacker can trick
    Thunderbird into including a directory listing of /tmp when the message is forwarded or edited as a new
    message. This vulnerability could allow attackers to disclose sensitive information from the victim's
    system. This vulnerability is not limited to Linux; similar behavior has been observed on Windows as well.
    (CVE-2025-2830)

  - When an email contains multiple attachments with external links via the X-Mozilla-External-Attachment-URL
    header, only the last link is shown when hovering over any attachment. Although the correct link is used
    on click, the misleading hover text could trick users into downloading content from untrusted sources.
    (CVE-2025-3523)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2025-26/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Thunderbird version 137.0.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-3522");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/04/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_thunderbird_installed.nasl");
  script_require_keys("MacOSX/Thunderbird/Installed");

  exit(0);
}

include('mozilla_version.inc');

var kb_base = 'MacOSX/Thunderbird';
get_kb_item_or_exit(kb_base+'/Installed');

var version = get_kb_item_or_exit(kb_base+'/Version', exit_code:1);
var path = get_kb_item_or_exit(kb_base+'/Path', exit_code:1);

var is_esr = get_kb_item(kb_base+'/is_esr');
if (is_esr) exit(0, 'The Mozilla Thunderbird installation is in the ESR branch.');

mozilla_check_version(version:version, path:path, product:'thunderbird', esr:FALSE, fix:'137.0.2', severity:SECURITY_WARNING);
