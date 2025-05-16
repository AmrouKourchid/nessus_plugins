#%NASL_MIN_LEVEL 80900
## 
# (C) Tenable, Inc.
#                                  
# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2024-35.
# The text itself is copyright (C) Mozilla Foundation.
##

include('compat.inc');

if (description)
{
  script_id(205015);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/06");

  script_cve_id(
    "CVE-2024-7518",
    "CVE-2024-7519",
    "CVE-2024-7520",
    "CVE-2024-7521",
    "CVE-2024-7522",
    "CVE-2024-7524",
    "CVE-2024-7525",
    "CVE-2024-7526",
    "CVE-2024-7527",
    "CVE-2024-7528",
    "CVE-2024-7529",
    "CVE-2024-7531"
  );
  script_xref(name:"IAVA", value:"2024-A-0465-S");

  script_name(english:"Mozilla Firefox ESR < 128.1");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS or Mac OS X host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Firefox ESR installed on the remote macOS or Mac OS X host is prior to 128.1. It is, therefore, affected
by multiple vulnerabilities as referenced in the mfsa2024-35 advisory.

  - Select options could obscure the fullscreen notification dialog. This could be used by a malicious site to
    perform a spoofing attack. (CVE-2024-7518)

  - Insufficient checks when processing graphics shared memory could have led to memory corruption. This could
    be leveraged by an attacker to perform a sandbox escape. (CVE-2024-7519)

  - A type confusion bug in WebAssembly could be leveraged by an attacker to potentially achieve code
    execution. (CVE-2024-7520)

  - Incomplete WebAssembly exception handing could have led to a use-after-free. (CVE-2024-7521)

  - Editor code failed to check an attribute value. This could have led to an out-of-bounds read.
    (CVE-2024-7522)

  - Firefox adds web-compatibility shims in place of some tracking scripts blocked by Enhanced Tracking
    Protection.  On a site protected by Content Security Policy in strict-dynamic mode, an attacker able to
    inject an HTML element could have used a DOM Clobbering attack on some of the shims and achieved XSS,
    bypassing the CSP strict-dynamic protection. (CVE-2024-7524)

  - It was possible for a web extension with minimal permissions to create a <code>StreamFilter</code> which
    could be used to read and modify the response body of requests on any site. (CVE-2024-7525)

  - ANGLE failed to initialize parameters which led to reading from uninitialized memory. This could be
    leveraged to leak sensitive data from memory. (CVE-2024-7526)

  - Unexpected marking work at the start of sweeping could have led to a use-after-free. (CVE-2024-7527)

  - Incorrect garbage collection interaction in IndexedDB could have led to a use-after-free. (CVE-2024-7528)

  - The date picker could partially obscure security prompts. This could be used by a malicious site to trick
    a user into granting permissions. (CVE-2024-7529)

  - Calling PK11Encrypt() in NSS using CKMCHACHA20 and the same buffer for input and output can result in
    plaintext on an Intel Sandy Bridge processor. In Firefox this only affects the QUIC header protection
    feature when the connection is using the ChaCha20-Poly1305 cipher suite. The most likely outcome is
    connection failure, but if the connection persists despite the high packet loss it could be possible for a
    network observer to identify packets as coming from the same source despite a network path change.
    (CVE-2024-7531)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2024-35/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Firefox ESR version 128.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-7528");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-7519");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/08/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox_esr");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_firefox_installed.nasl");
  script_require_keys("MacOSX/Firefox/Version");

  exit(0);
}

include('mozilla_version.inc');

var kb_base = 'MacOSX/Firefox';
get_kb_item_or_exit(kb_base+'/Installed');

var version = get_kb_item_or_exit(kb_base+'/Version', exit_code:1);
var path = get_kb_item_or_exit(kb_base+'/Path', exit_code:1);

var is_esr = get_kb_item(kb_base+'/is_esr');
if (isnull(is_esr)) audit(AUDIT_NOT_INST, 'Mozilla Firefox ESR');

mozilla_check_version(version:version, path:path, product:'firefox', esr:TRUE, fix:'128.1', min:'128.0.0', severity:SECURITY_HOLE);
