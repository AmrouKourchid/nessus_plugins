#%NASL_MIN_LEVEL 80900
## 
# (C) Tenable, Inc.
#                                  
# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2023-56.
# The text itself is copyright (C) Mozilla Foundation.
##

include('compat.inc');

if (description)
{
  script_id(187080);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/26");

  script_cve_id(
    "CVE-2023-6135",
    "CVE-2023-6856",
    "CVE-2023-6857",
    "CVE-2023-6858",
    "CVE-2023-6859",
    "CVE-2023-6860",
    "CVE-2023-6861",
    "CVE-2023-6863",
    "CVE-2023-6864",
    "CVE-2023-6865",
    "CVE-2023-6866",
    "CVE-2023-6867",
    "CVE-2023-6868",
    "CVE-2023-6869",
    "CVE-2023-6870",
    "CVE-2023-6871",
    "CVE-2023-6872",
    "CVE-2023-6873"
  );
  script_xref(name:"IAVA", value:"2023-A-0702-S");

  script_name(english:"Mozilla Firefox < 121.0");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS or Mac OS X host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Firefox installed on the remote macOS or Mac OS X host is prior to 121.0. It is, therefore, affected by
multiple vulnerabilities as referenced in the mfsa2023-56 advisory.

  - The WebGL <code>DrawElementsInstanced</code> method was susceptible to a heap buffer overflow when used on
    systems with the Mesa VM driver. This issue could allow an attacker to perform remote code execution and
    sandbox escape. (CVE-2023-6856)

  - Multiple NSS NIST curves were susceptible to a side-channel attack known as Minerva. This attack could
    potentially allow an attacker to recover the private key. (CVE-2023-6135)

  - <code>EncryptingOutputStream</code> was susceptible to exposing uninitialized data. This issue could only
    be abused in order to write data to a local disk which may have implications for private browsing mode.
    (CVE-2023-6865)

  - When resolving a symlink, a race may occur where the buffer passed to <code>readlink</code> may actually
    be smaller than necessary.  This bug only affects Firefox on Unix-based operating systems (Android, Linux,
    MacOS). Windows is unaffected. (CVE-2023-6857)

  - Firefox was susceptible to a heap buffer overflow in <code>nsTextFragment</code> due to insufficient OOM
    handling. (CVE-2023-6858)

  - A use-after-free condition affected TLS socket creation when under memory pressure. (CVE-2023-6859)

  - TypedArrays can be fallible and lacked proper exception handling. This could lead to abuse in other APIs
    which expect TypedArrays to always succeed. (CVE-2023-6866)

  - The <code>VideoBridge</code> allowed any content process to use textures produced by remote decoders. This
    could be abused to escape the sandbox. (CVE-2023-6860)

  - The timing of a button click causing a popup to disappear was approximately the same length as the anti-
    clickjacking delay on permission prompts. It was possible to use this fact to surprise users by luring
    them to click where the permission grant button would be about to appear. (CVE-2023-6867)

  - The <code>nsWindow::PickerOpen(void)</code> method was susceptible to a heap buffer overflow when running
    in headless mode. (CVE-2023-6861)

  - In some instances, the user-agent would allow push requests which lacked a valid VAPID even though the
    push manager subscription defined one. This could allow empty messages to be sent from unauthorized
    parties. This bug only affects Firefox on Android. (CVE-2023-6868)

  - A <code><dialog></code> element could have been manipulated to paint content outside of a sandboxed
    iframe. This could allow untrusted content to display under the guise of trusted content. (CVE-2023-6869)

  - Applications which spawn a Toast notification in a background thread may have obscured fullscreen
    notifications displayed by Firefox.  This issue only affects Android versions of Firefox and Firefox
    Focus. (CVE-2023-6870)

  - Under certain conditions, Firefox did not display a warning when a user attempted to navigate to a new
    protocol handler. (CVE-2023-6871)

  - Browser tab titles were being leaked by GNOME to system logs. This could potentially expose the browsing
    habits of users running in a private tab. (CVE-2023-6872)

  - The <code>ShutdownObserver()</code> was susceptible to potentially undefined behavior due to its reliance
    on a dynamic type that lacked a virtual destructor. (CVE-2023-6863)

  - Memory safety bugs present in Firefox 120, Firefox ESR 115.5, and Thunderbird 115.5. Some of these bugs
    showed evidence of memory corruption and we presume that with enough effort some of these could have been
    exploited to run arbitrary code. (CVE-2023-6864)

  - Memory safety bugs present in Firefox 120. Some of these bugs showed evidence of memory corruption and we
    presume that with enough effort some of these could have been exploited to run arbitrary code.
    (CVE-2023-6873)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2023-56/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Firefox version 121.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-6873");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/12/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/12/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/12/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

mozilla_check_version(version:version, path:path, product:'firefox', esr:FALSE, fix:'121.0', severity:SECURITY_HOLE);
