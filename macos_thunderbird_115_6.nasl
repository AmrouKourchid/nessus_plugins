#%NASL_MIN_LEVEL 80900
## 
# (C) Tenable, Inc.
#                                  
# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2023-55.
# The text itself is copyright (C) Mozilla Foundation.
##

include('compat.inc');

if (description)
{
  script_id(187075);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/12/25");

  script_cve_id(
    "CVE-2023-6856",
    "CVE-2023-6857",
    "CVE-2023-6858",
    "CVE-2023-6859",
    "CVE-2023-6860",
    "CVE-2023-6861",
    "CVE-2023-6862",
    "CVE-2023-6863",
    "CVE-2023-6864",
    "CVE-2023-50761",
    "CVE-2023-50762"
  );

  script_name(english:"Mozilla Thunderbird < 115.6");

  script_set_attribute(attribute:"synopsis", value:
"A mail client installed on the remote macOS or Mac OS X host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Thunderbird installed on the remote macOS or Mac OS X host is prior to 115.6. It is, therefore, affected
by multiple vulnerabilities as referenced in the mfsa2023-55 advisory.

  - When processing a PGP/MIME payload that contains digitally signed text, the first paragraph of the text
    was never shown to the user. This is because the text was interpreted as a MIME message and the first
    paragraph was always treated as an email header section. A digitally signed text from a different context,
    such as a signed GIT commit, could be used to spoof an email message. (CVE-2023-50762)

  - The signature of a digitally signed S/MIME email message may optionally specify the signature creation
    date and time. If present, Thunderbird did not compare the signature creation date with the message date
    and time, and displayed a valid signature despite a date or time mismatch. This could be used to give
    recipients the impression that a message was sent at a different date or time. (CVE-2023-50761)

  - The WebGL <code>DrawElementsInstanced</code> method was susceptible to a heap buffer overflow when used on
    systems with the Mesa VM driver.  This issue could allow an attacker to perform remote code execution and
    sandbox escape. (CVE-2023-6856)

  - When resolving a symlink, a race may occur where the buffer passed to <code>readlink</code> may actually
    be smaller than necessary.  This bug only affects Thunderbird on Unix-based operating systems (Android,
    Linux, MacOS). Windows is unaffected. (CVE-2023-6857)

  - Thunderbird was susceptible to a heap buffer overflow in <code>nsTextFragment</code> due to insufficient
    OOM handling. (CVE-2023-6858)

  - A use-after-free condition affected TLS socket creation when under memory pressure. (CVE-2023-6859)

  - The <code>VideoBridge</code> allowed any content process to use textures produced by remote decoders.
    This could be abused to escape the sandbox. (CVE-2023-6860)

  - The <code>nsWindow::PickerOpen(void)</code> method was susceptible to a heap buffer overflow when running
    in headless mode. (CVE-2023-6861)

  - A use-after-free was identified in the <code>nsDNSService::Init</code>.  This issue appears to manifest
    rarely during start-up. (CVE-2023-6862)

  - The <code>ShutdownObserver()</code> was susceptible to potentially undefined behavior due to its reliance
    on a dynamic type that lacked a virtual destructor. (CVE-2023-6863)

  - Memory safety bugs present in Firefox 120, Firefox ESR 115.5, and Thunderbird 115.5. Some of these bugs
    showed evidence of memory corruption and we presume that with enough effort some of these could have been
    exploited to run arbitrary code. (CVE-2023-6864)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2023-55/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Thunderbird version 115.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-6864");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/12/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/12/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/12/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

mozilla_check_version(version:version, path:path, product:'thunderbird', esr:FALSE, fix:'115.6', severity:SECURITY_HOLE);
