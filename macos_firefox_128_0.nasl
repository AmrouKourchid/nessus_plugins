#%NASL_MIN_LEVEL 80900
## 
# (C) Tenable, Inc.
#                                  
# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2024-29.
# The text itself is copyright (C) Mozilla Foundation.
##

include('compat.inc');

if (description)
{
  script_id(202018);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/13");

  script_cve_id(
    "CVE-2024-6600",
    "CVE-2024-6601",
    "CVE-2024-6602",
    "CVE-2024-6603",
    "CVE-2024-6604",
    "CVE-2024-6605",
    "CVE-2024-6606",
    "CVE-2024-6607",
    "CVE-2024-6608",
    "CVE-2024-6609",
    "CVE-2024-6610",
    "CVE-2024-6611",
    "CVE-2024-6612",
    "CVE-2024-6613",
    "CVE-2024-6614",
    "CVE-2024-6615"
  );
  script_xref(name:"IAVA", value:"2024-A-0386-S");

  script_name(english:"Mozilla Firefox < 128.0");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS or Mac OS X host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Firefox installed on the remote macOS or Mac OS X host is prior to 128.0. It is, therefore, affected by
multiple vulnerabilities as referenced in the mfsa2024-29 advisory.

  - Firefox Android allowed immediate interaction with permission prompts. This could be used for tapjacking.
    (CVE-2024-6605)

  - Clipboard code failed to check the index on an array access. This could have lead to an out-of-bounds
    read. (CVE-2024-6606)

  - It was possible to prevent a user from exiting pointerlock when pressing escape and to overlay
    customValidity notifications from a <code><select></code> element over certain permission prompts.
    This could be used to confuse a user into giving a site unintended permissions. (CVE-2024-6607)

  - It was possible to move the cursor using pointerlock from an iframe. This allowed moving the cursor
    outside of the viewport and the Firefox window. (CVE-2024-6608)

  - When almost out-of-memory an elliptic curve key which was never allocated could have been freed again.
    (CVE-2024-6609)

  - Form validation popups could capture escape key presses. Therefore, spamming form validation messages
    could be used to prevent users from exiting full-screen mode. (CVE-2024-6610)

  - Due to large allocation checks in Angle for GLSL shaders being too lenient an out-of-bounds access could
    occur when allocating more than 8192 ints in private shader memory on mac OS. (CVE-2024-6600)

  - A race condition could lead to a cross-origin container obtaining permissions of the top-level origin.
    (CVE-2024-6601)

  - A mismatch between allocator and deallocator could have lead to memory corruption. (CVE-2024-6602)

  - In an out-of-memory scenario an allocation could fail but free would have been called on the pointer
    afterwards leading to memory corruption. (CVE-2024-6603)

  - A nested iframe, triggering a cross-site navigation, could send SameSite=Strict or Lax cookies.
    (CVE-2024-6611)

  - CSP violations generated links in the console tab of the developer tools, pointing to the violating
    resource. This caused a DNS prefetch which leaked that a CSP violation happened. (CVE-2024-6612)

  - The frame iterator could get stuck in a loop when encountering certain wasm frames leading to incorrect
    stack traces. (CVE-2024-6613, CVE-2024-6614)

  - Memory safety bugs present in Firefox 127, Firefox ESR 115.12, and Thunderbird 115.12. Some of these bugs
    showed evidence of memory corruption and we presume that with enough effort some of these could have been
    exploited to run arbitrary code. (CVE-2024-6604)

  - Memory safety bugs present in Firefox 127 and Thunderbird 127. Some of these bugs showed evidence of
    memory corruption and we presume that with enough effort some of these could have been exploited to run
    arbitrary code. (CVE-2024-6615)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2024-29/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Firefox version 128.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-6609");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_firefox_installed.nasl");
  script_require_keys("MacOSX/Firefox/Installed");

  exit(0);
}

include('mozilla_version.inc');

var kb_base = 'MacOSX/Firefox';
get_kb_item_or_exit(kb_base+'/Installed');

var version = get_kb_item_or_exit(kb_base+'/Version', exit_code:1);
var path = get_kb_item_or_exit(kb_base+'/Path', exit_code:1);

var is_esr = get_kb_item(kb_base+'/is_esr');
if (is_esr) exit(0, 'The Mozilla Firefox installation is in the ESR branch.');

mozilla_check_version(version:version, path:path, product:'firefox', esr:FALSE, fix:'128.0', severity:SECURITY_HOLE);
