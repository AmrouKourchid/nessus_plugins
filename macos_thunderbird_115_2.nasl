#%NASL_MIN_LEVEL 80900
## 
# (C) Tenable, Inc.
#                                  
# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2023-38.
# The text itself is copyright (C) Mozilla Foundation.
##

include('compat.inc');

if (description)
{
  script_id(180323);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/09/26");

  script_cve_id(
    "CVE-2023-4051",
    "CVE-2023-4053",
    "CVE-2023-4573",
    "CVE-2023-4574",
    "CVE-2023-4575",
    "CVE-2023-4576",
    "CVE-2023-4577",
    "CVE-2023-4578",
    "CVE-2023-4580",
    "CVE-2023-4581",
    "CVE-2023-4582",
    "CVE-2023-4583",
    "CVE-2023-4584",
    "CVE-2023-4585"
  );
  script_xref(name:"IAVA", value:"2023-A-0449-S");

  script_name(english:"Mozilla Thunderbird < 115.2");

  script_set_attribute(attribute:"synopsis", value:
"A mail client installed on the remote macOS or Mac OS X host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Thunderbird installed on the remote macOS or Mac OS X host is prior to 115.2. It is, therefore, affected
by multiple vulnerabilities as referenced in the mfsa2023-38 advisory.

  - When receiving rendering data over IPC <code>mStream</code> could have been destroyed when initialized,
    which could have led to a use-after-free causing a potentially exploitable crash. (CVE-2023-4573)

  - When creating a callback over IPC for showing the Color Picker window, multiple of the same callbacks
    could have been created at a time and eventually all simultaneously destroyed as soon as one of the
    callbacks finished. This could have led to a use-after-free causing a potentially exploitable crash.
    (CVE-2023-4574)

  - When creating a callback over IPC for showing the File Picker window, multiple of the same callbacks could
    have been created at a time and eventually all simultaneously destroyed as soon as one of the callbacks
    finished. This could have led to a use-after-free causing a potentially exploitable crash. (CVE-2023-4575)

  - On Windows, an integer overflow could occur in <code>RecordedSourceSurfaceCreation</code> which resulted
    in a heap buffer overflow potentially leaking sensitive data that could have led to a sandbox escape. This
    bug only affects Firefox on Windows. Other operating systems are unaffected. (CVE-2023-4576)

  - When <code>UpdateRegExpStatics</code> attempted to access <code>initialStringHeap</code> it could already
    have been garbage collected prior to entering the function, which could potentially have led to an
    exploitable crash. (CVE-2023-4577)

  - A website could have obscured the full screen notification by using the file open dialog. This could have
    led to user confusion and possible spoofing attacks. (CVE-2023-4051)

  - When calling <code>JS::CheckRegExpSyntax</code> a Syntax Error could have been set which would end in
    calling <code>convertToRuntimeErrorAndClear</code>. A path in the function could attempt to allocate
    memory when none is available which would have caused a newly created Out of Memory exception to be
    mishandled as a Syntax Error. (CVE-2023-4578)

  - A website could have obscured the full screen notification by using a URL with a scheme handled by an
    external program, such as a mailto URL. This could have led to user confusion and possible spoofing
    attacks. (CVE-2023-4053)

  - Push notifications stored on disk in private browsing mode were not being encrypted potentially allowing
    the leak of sensitive information. (CVE-2023-4580)

  - Excel <code>.xll</code> add-in files did not have a blocklist entry in Firefox's executable blocklist
    which allowed them to be downloaded without any warning of their potential harm. (CVE-2023-4581)

  - Due to large allocation checks in Angle for glsl shaders being too lenient a buffer overflow could have
    occured when allocating too much private shader memory on mac OS.  This bug only affects Firefox on macOS.
    Other operating systems are unaffected. (CVE-2023-4582)

  - When checking if the Browsing Context had been discarded in <code>HttpBaseChannel</code>, if the load
    group was not available then it was assumed to have already been discarded which was not always the case
    for private channels after the private session had ended. (CVE-2023-4583)

  - Memory safety bugs present in Firefox 116, Firefox ESR 102.14, Firefox ESR 115.1, Thunderbird 102.14, and
    Thunderbird 115.1. Some of these bugs showed evidence of memory corruption and we presume that with enough
    effort some of these could have been exploited to run arbitrary code. (CVE-2023-4584)

  - Memory safety bugs present in Firefox 116, Firefox ESR 115.1, and Thunderbird 115.1. Some of these bugs
    showed evidence of memory corruption and we presume that with enough effort some of these could have been
    exploited to run arbitrary code. (CVE-2023-4585)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2023-38/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Thunderbird version 115.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-4585");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/08/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/08/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/08/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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

mozilla_check_version(version:version, path:path, product:'thunderbird', esr:FALSE, fix:'115.2', severity:SECURITY_HOLE);
