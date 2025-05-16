#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202402-25.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(190759);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/20");

  script_cve_id(
    "CVE-2023-3417",
    "CVE-2023-3600",
    "CVE-2023-4045",
    "CVE-2023-4046",
    "CVE-2023-4047",
    "CVE-2023-4048",
    "CVE-2023-4049",
    "CVE-2023-4050",
    "CVE-2023-4051",
    "CVE-2023-4052",
    "CVE-2023-4053",
    "CVE-2023-4054",
    "CVE-2023-4055",
    "CVE-2023-4056",
    "CVE-2023-4057",
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
    "CVE-2023-4585",
    "CVE-2023-5168",
    "CVE-2023-5169",
    "CVE-2023-5171",
    "CVE-2023-5174",
    "CVE-2023-5176",
    "CVE-2023-5721",
    "CVE-2023-5724",
    "CVE-2023-5725",
    "CVE-2023-5726",
    "CVE-2023-5727",
    "CVE-2023-5728",
    "CVE-2023-5730",
    "CVE-2023-5732",
    "CVE-2023-6204",
    "CVE-2023-6205",
    "CVE-2023-6206",
    "CVE-2023-6207",
    "CVE-2023-6208",
    "CVE-2023-6209",
    "CVE-2023-6212",
    "CVE-2023-6856",
    "CVE-2023-6857",
    "CVE-2023-6858",
    "CVE-2023-6859",
    "CVE-2023-6860",
    "CVE-2023-6861",
    "CVE-2023-6862",
    "CVE-2023-6863",
    "CVE-2023-6864",
    "CVE-2023-37201",
    "CVE-2023-37202",
    "CVE-2023-37207",
    "CVE-2023-37208",
    "CVE-2023-37211",
    "CVE-2023-50761",
    "CVE-2023-50762",
    "CVE-2024-0741",
    "CVE-2024-0742",
    "CVE-2024-0746",
    "CVE-2024-0747",
    "CVE-2024-0749",
    "CVE-2024-0750",
    "CVE-2024-0751",
    "CVE-2024-0753",
    "CVE-2024-0755"
  );

  script_name(english:"GLSA-202402-25 : Mozilla Thunderbird: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202402-25 (Mozilla Thunderbird: Multiple
Vulnerabilities)

  - Thunderbird allowed the Text Direction Override Unicode Character in filenames. An email attachment could
    be incorrectly shown as being a document file, while in fact it was an executable file. Newer versions of
    Thunderbird will strip the character and show the correct file extension. This vulnerability affects
    Thunderbird < 115.0.1 and Thunderbird < 102.13.1. (CVE-2023-3417)

  - During the worker lifecycle, a use-after-free condition could have occured, which could have led to a
    potentially exploitable crash. This vulnerability affects Firefox < 115.0.2, Firefox ESR < 115.0.2, and
    Thunderbird < 115.0.1. (CVE-2023-3600)

  - Offscreen Canvas did not properly track cross-origin tainting, which could have been used to access image
    data from another site in violation of same-origin policy. This vulnerability affects Firefox < 116,
    Firefox ESR < 102.14, and Firefox ESR < 115.1. (CVE-2023-4045)

  - In some circumstances, a stale value could have been used for a global variable in WASM JIT analysis. This
    resulted in incorrect compilation and a potentially exploitable crash in the content process. This
    vulnerability affects Firefox < 116, Firefox ESR < 102.14, and Firefox ESR < 115.1. (CVE-2023-4046)

  - A bug in popup notifications delay calculation could have made it possible for an attacker to trick a user
    into granting permissions. This vulnerability affects Firefox < 116, Firefox ESR < 102.14, and Firefox ESR
    < 115.1. (CVE-2023-4047)

  - An out-of-bounds read could have led to an exploitable crash when parsing HTML with DOMParser in low
    memory situations. This vulnerability affects Firefox < 116, Firefox ESR < 102.14, and Firefox ESR <
    115.1. (CVE-2023-4048)

  - Race conditions in reference counting code were found through code inspection. These could have resulted
    in potentially exploitable use-after-free vulnerabilities. This vulnerability affects Firefox < 116,
    Firefox ESR < 102.14, and Firefox ESR < 115.1. (CVE-2023-4049)

  - In some cases, an untrusted input stream was copied to a stack buffer without checking its size. This
    resulted in a potentially exploitable crash which could have led to a sandbox escape. This vulnerability
    affects Firefox < 116, Firefox ESR < 102.14, and Firefox ESR < 115.1. (CVE-2023-4050)

  - A website could have obscured the full screen notification by using the file open dialog. This could have
    led to user confusion and possible spoofing attacks. This vulnerability affects Firefox < 116, Firefox ESR
    < 115.2, and Thunderbird < 115.2. (CVE-2023-4051)

  - The Firefox updater created a directory writable by non-privileged users. When uninstalling Firefox, any
    files in that directory would be recursively deleted with the permissions of the uninstalling user
    account. This could be combined with creation of a junction (a form of symbolic link) to allow arbitrary
    file deletion controlled by the non-privileged user. *This bug only affects Firefox on Windows. Other
    operating systems are unaffected.* This vulnerability affects Firefox < 116, Firefox ESR < 115.1, and
    Thunderbird < 115.1. (CVE-2023-4052)

  - A website could have obscured the full screen notification by using a URL with a scheme handled by an
    external program, such as a mailto URL. This could have led to user confusion and possible spoofing
    attacks. This vulnerability affects Firefox < 116, Firefox ESR < 115.2, and Thunderbird < 115.2.
    (CVE-2023-4053)

  - When opening appref-ms files, Firefox did not warn the user that these files may contain malicious code.
    *This bug only affects Firefox on Windows. Other operating systems are unaffected.* This vulnerability
    affects Firefox < 116, Firefox ESR < 102.14, Firefox ESR < 115.1, Thunderbird < 102.14, and Thunderbird <
    115.1. (CVE-2023-4054)

  - When the number of cookies per domain was exceeded in `document.cookie`, the actual cookie jar sent to the
    host was no longer consistent with expected cookie jar state. This could have caused requests to be sent
    with some cookies missing. This vulnerability affects Firefox < 116, Firefox ESR < 102.14, and Firefox ESR
    < 115.1. (CVE-2023-4055)

  - Memory safety bugs present in Firefox 115, Firefox ESR 115.0, Firefox ESR 102.13, Thunderbird 115.0, and
    Thunderbird 102.13. Some of these bugs showed evidence of memory corruption and we presume that with
    enough effort some of these could have been exploited to run arbitrary code. This vulnerability affects
    Firefox < 116, Firefox ESR < 102.14, and Firefox ESR < 115.1. (CVE-2023-4056)

  - Memory safety bugs present in Firefox 115, Firefox ESR 115.0, and Thunderbird 115.0. Some of these bugs
    showed evidence of memory corruption and we presume that with enough effort some of these could have been
    exploited to run arbitrary code. This vulnerability affects Firefox < 116, Firefox ESR < 115.1, and
    Thunderbird < 115.1. (CVE-2023-4057)

  - When receiving rendering data over IPC `mStream` could have been destroyed when initialized, which could
    have led to a use-after-free causing a potentially exploitable crash. This vulnerability affects Firefox <
    117, Firefox ESR < 102.15, Firefox ESR < 115.2, Thunderbird < 102.15, and Thunderbird < 115.2.
    (CVE-2023-4573)

  - When creating a callback over IPC for showing the Color Picker window, multiple of the same callbacks
    could have been created at a time and eventually all simultaneously destroyed as soon as one of the
    callbacks finished. This could have led to a use-after-free causing a potentially exploitable crash. This
    vulnerability affects Firefox < 117, Firefox ESR < 102.15, Firefox ESR < 115.2, Thunderbird < 102.15, and
    Thunderbird < 115.2. (CVE-2023-4574)

  - When creating a callback over IPC for showing the File Picker window, multiple of the same callbacks could
    have been created at a time and eventually all simultaneously destroyed as soon as one of the callbacks
    finished. This could have led to a use-after-free causing a potentially exploitable crash. This
    vulnerability affects Firefox < 117, Firefox ESR < 102.15, Firefox ESR < 115.2, Thunderbird < 102.15, and
    Thunderbird < 115.2. (CVE-2023-4575)

  - On Windows, an integer overflow could occur in `RecordedSourceSurfaceCreation` which resulted in a heap
    buffer overflow potentially leaking sensitive data that could have led to a sandbox escape. *This bug only
    affects Firefox on Windows. Other operating systems are unaffected.* This vulnerability affects Firefox <
    117, Firefox ESR < 102.15, Firefox ESR < 115.2, Thunderbird < 102.15, and Thunderbird < 115.2.
    (CVE-2023-4576)

  - When `UpdateRegExpStatics` attempted to access `initialStringHeap` it could already have been garbage
    collected prior to entering the function, which could potentially have led to an exploitable crash. This
    vulnerability affects Firefox < 117, Firefox ESR < 115.2, and Thunderbird < 115.2. (CVE-2023-4577)

  - When calling `JS::CheckRegExpSyntax` a Syntax Error could have been set which would end in calling
    `convertToRuntimeErrorAndClear`. A path in the function could attempt to allocate memory when none is
    available which would have caused a newly created Out of Memory exception to be mishandled as a Syntax
    Error. This vulnerability affects Firefox < 117, Firefox ESR < 115.2, and Thunderbird < 115.2.
    (CVE-2023-4578)

  - Push notifications stored on disk in private browsing mode were not being encrypted potentially allowing
    the leak of sensitive information. This vulnerability affects Firefox < 117, Firefox ESR < 115.2, and
    Thunderbird < 115.2. (CVE-2023-4580)

  - Excel `.xll` add-in files did not have a blocklist entry in Firefox's executable blocklist which allowed
    them to be downloaded without any warning of their potential harm. This vulnerability affects Firefox <
    117, Firefox ESR < 102.15, Firefox ESR < 115.2, Thunderbird < 102.15, and Thunderbird < 115.2.
    (CVE-2023-4581)

  - Due to large allocation checks in Angle for glsl shaders being too lenient a buffer overflow could have
    occured when allocating too much private shader memory on mac OS. *This bug only affects Firefox on macOS.
    Other operating systems are unaffected.* This vulnerability affects Firefox < 117, Firefox ESR < 115.2,
    and Thunderbird < 115.2. (CVE-2023-4582)

  - When checking if the Browsing Context had been discarded in `HttpBaseChannel`, if the load group was not
    available then it was assumed to have already been discarded which was not always the case for private
    channels after the private session had ended. This vulnerability affects Firefox < 117, Firefox ESR <
    115.2, and Thunderbird < 115.2. (CVE-2023-4583)

  - Memory safety bugs present in Firefox 116, Firefox ESR 102.14, Firefox ESR 115.1, Thunderbird 102.14, and
    Thunderbird 115.1. Some of these bugs showed evidence of memory corruption and we presume that with enough
    effort some of these could have been exploited to run arbitrary code. This vulnerability affects Firefox <
    117, Firefox ESR < 102.15, Firefox ESR < 115.2, Thunderbird < 102.15, and Thunderbird < 115.2.
    (CVE-2023-4584)

  - Memory safety bugs present in Firefox 116, Firefox ESR 115.1, and Thunderbird 115.1. Some of these bugs
    showed evidence of memory corruption and we presume that with enough effort some of these could have been
    exploited to run arbitrary code. This vulnerability affects Firefox < 117, Firefox ESR < 115.2, and
    Thunderbird < 115.2. (CVE-2023-4585)

  - A compromised content process could have provided malicious data to `FilterNodeD2D1` resulting in an out-
    of-bounds write, leading to a potentially exploitable crash in a privileged process. *This bug only
    affects Firefox on Windows. Other operating systems are unaffected.* This vulnerability affects Firefox <
    118, Firefox ESR < 115.3, and Thunderbird < 115.3. (CVE-2023-5168)

  - A compromised content process could have provided malicious data in a `PathRecording` resulting in an out-
    of-bounds write, leading to a potentially exploitable crash in a privileged process. This vulnerability
    affects Firefox < 118, Firefox ESR < 115.3, and Thunderbird < 115.3. (CVE-2023-5169)

  - During Ion compilation, a Garbage Collection could have resulted in a use-after-free condition, allowing
    an attacker to write two NUL bytes, and cause a potentially exploitable crash. This vulnerability affects
    Firefox < 118, Firefox ESR < 115.3, and Thunderbird < 115.3. (CVE-2023-5171)

  - If Windows failed to duplicate a handle during process creation, the sandbox code may have inadvertently
    freed a pointer twice, resulting in a use-after-free and a potentially exploitable crash. *This bug only
    affects Firefox on Windows when run in non-standard configurations (such as using `runas`). Other
    operating systems are unaffected.* This vulnerability affects Firefox < 118, Firefox ESR < 115.3, and
    Thunderbird < 115.3. (CVE-2023-5174)

  - Memory safety bugs present in Firefox 117, Firefox ESR 115.2, and Thunderbird 115.2. Some of these bugs
    showed evidence of memory corruption and we presume that with enough effort some of these could have been
    exploited to run arbitrary code. This vulnerability affects Firefox < 118, Firefox ESR < 115.3, and
    Thunderbird < 115.3. (CVE-2023-5176)

  - It was possible for certain browser prompts and dialogs to be activated or dismissed unintentionally by
    the user due to an insufficient activation-delay. This vulnerability affects Firefox < 119, Firefox ESR <
    115.4, and Thunderbird < 115.4.1. (CVE-2023-5721)

  - Drivers are not always robust to extremely large draw calls and in some cases this scenario could have led
    to a crash. This vulnerability affects Firefox < 119, Firefox ESR < 115.4, and Thunderbird < 115.4.1.
    (CVE-2023-5724)

  - A malicious installed WebExtension could open arbitrary URLs, which under the right circumstance could be
    leveraged to collect sensitive user data. This vulnerability affects Firefox < 119, Firefox ESR < 115.4,
    and Thunderbird < 115.4.1. (CVE-2023-5725)

  - A website could have obscured the full screen notification by using the file open dialog. This could have
    led to user confusion and possible spoofing attacks. *Note: This issue only affected macOS operating
    systems. Other operating systems are unaffected.* This vulnerability affects Firefox < 119, Firefox ESR <
    115.4, and Thunderbird < 115.4.1. (CVE-2023-5726)

  - The executable file warning was not presented when downloading .msix, .msixbundle, .appx, and .appxbundle
    files, which can run commands on a user's computer. *Note: This issue only affected Windows operating
    systems. Other operating systems are unaffected.* This vulnerability affects Firefox < 119, Firefox ESR <
    115.4, and Thunderbird < 115.4.1. (CVE-2023-5727)

  - During garbage collection extra operations were performed on a object that should not be. This could have
    led to a potentially exploitable crash. This vulnerability affects Firefox < 119, Firefox ESR < 115.4, and
    Thunderbird < 115.4.1. (CVE-2023-5728)

  - Memory safety bugs present in Firefox 118, Firefox ESR 115.3, and Thunderbird 115.3. Some of these bugs
    showed evidence of memory corruption and we presume that with enough effort some of these could have been
    exploited to run arbitrary code. This vulnerability affects Firefox < 119, Firefox ESR < 115.4, and
    Thunderbird < 115.4.1. (CVE-2023-5730)

  - An attacker could have created a malicious link using bidirectional characters to spoof the location in
    the address bar when visited. This vulnerability affects Firefox < 117, Firefox ESR < 115.4, and
    Thunderbird < 115.4.1. (CVE-2023-5732)

  - On some systemsdepending on the graphics settings and driversit was possible to force an out-of-bounds
    read and leak memory data into the images created on the canvas element. This vulnerability affects
    Firefox < 120, Firefox ESR < 115.5.0, and Thunderbird < 115.5. (CVE-2023-6204)

  - It was possible to cause the use of a MessagePort after it had already been freed, which could potentially
    have led to an exploitable crash. This vulnerability affects Firefox < 120, Firefox ESR < 115.5.0, and
    Thunderbird < 115.5. (CVE-2023-6205)

  - The black fade animation when exiting fullscreen is roughly the length of the anti-clickjacking delay on
    permission prompts. It was possible to use this fact to surprise users by luring them to click where the
    permission grant button would be about to appear. This vulnerability affects Firefox < 120, Firefox ESR <
    115.5.0, and Thunderbird < 115.5. (CVE-2023-6206)

  - Ownership mismanagement led to a use-after-free in ReadableByteStreams This vulnerability affects Firefox
    < 120, Firefox ESR < 115.5.0, and Thunderbird < 115.5. (CVE-2023-6207)

  - When using X11, text selected by the page using the Selection API was erroneously copied into the primary
    selection, a temporary storage not unlike the clipboard. *This bug only affects Firefox on X11. Other
    systems are unaffected.* This vulnerability affects Firefox < 120, Firefox ESR < 115.5.0, and Thunderbird
    < 115.5. (CVE-2023-6208)

  - Relative URLs starting with three slashes were incorrectly parsed, and a path-traversal /../ part in the
    path could be used to override the specified host. This could contribute to security problems in web
    sites. This vulnerability affects Firefox < 120, Firefox ESR < 115.5.0, and Thunderbird < 115.5.
    (CVE-2023-6209)

  - Memory safety bugs present in Firefox 119, Firefox ESR 115.4, and Thunderbird 115.4. Some of these bugs
    showed evidence of memory corruption and we presume that with enough effort some of these could have been
    exploited to run arbitrary code. This vulnerability affects Firefox < 120, Firefox ESR < 115.5.0, and
    Thunderbird < 115.5. (CVE-2023-6212)

  - The WebGL `DrawElementsInstanced` method was susceptible to a heap buffer overflow when used on systems
    with the Mesa VM driver. This issue could allow an attacker to perform remote code execution and sandbox
    escape. This vulnerability affects Firefox ESR < 115.6, Thunderbird < 115.6, and Firefox < 121.
    (CVE-2023-6856)

  - When resolving a symlink, a race may occur where the buffer passed to `readlink` may actually be smaller
    than necessary. *This bug only affects Firefox on Unix-based operating systems (Android, Linux, MacOS).
    Windows is unaffected.* This vulnerability affects Firefox ESR < 115.6, Thunderbird < 115.6, and Firefox <
    121. (CVE-2023-6857)

  - Firefox was susceptible to a heap buffer overflow in `nsTextFragment` due to insufficient OOM handling.
    This vulnerability affects Firefox ESR < 115.6, Thunderbird < 115.6, and Firefox < 121. (CVE-2023-6858)

  - A use-after-free condition affected TLS socket creation when under memory pressure. This vulnerability
    affects Firefox ESR < 115.6, Thunderbird < 115.6, and Firefox < 121. (CVE-2023-6859)

  - The `VideoBridge` allowed any content process to use textures produced by remote decoders. This could be
    abused to escape the sandbox. This vulnerability affects Firefox ESR < 115.6, Thunderbird < 115.6, and
    Firefox < 121. (CVE-2023-6860)

  - The `nsWindow::PickerOpen(void)` method was susceptible to a heap buffer overflow when running in headless
    mode. This vulnerability affects Firefox ESR < 115.6, Thunderbird < 115.6, and Firefox < 121.
    (CVE-2023-6861)

  - A use-after-free was identified in the `nsDNSService::Init`. This issue appears to manifest rarely during
    start-up. This vulnerability affects Firefox ESR < 115.6 and Thunderbird < 115.6. (CVE-2023-6862)

  - The `ShutdownObserver()` was susceptible to potentially undefined behavior due to its reliance on a
    dynamic type that lacked a virtual destructor. This vulnerability affects Firefox ESR < 115.6, Thunderbird
    < 115.6, and Firefox < 121. (CVE-2023-6863)

  - Memory safety bugs present in Firefox 120, Firefox ESR 115.5, and Thunderbird 115.5. Some of these bugs
    showed evidence of memory corruption and we presume that with enough effort some of these could have been
    exploited to run arbitrary code. This vulnerability affects Firefox ESR < 115.6, Thunderbird < 115.6, and
    Firefox < 121. (CVE-2023-6864)

  - An attacker could have triggered a use-after-free condition when creating a WebRTC connection over HTTPS.
    This vulnerability affects Firefox < 115, Firefox ESR < 102.13, and Thunderbird < 102.13. (CVE-2023-37201)

  - Cross-compartment wrappers wrapping a scripted proxy could have caused objects from other compartments to
    be stored in the main compartment resulting in a use-after-free. This vulnerability affects Firefox < 115,
    Firefox ESR < 102.13, and Thunderbird < 102.13. (CVE-2023-37202)

  - A website could have obscured the fullscreen notification by using a URL with a scheme handled by an
    external program, such as a mailto URL. This could have led to user confusion and possible spoofing
    attacks. This vulnerability affects Firefox < 115, Firefox ESR < 102.13, and Thunderbird < 102.13.
    (CVE-2023-37207)

  - When opening Diagcab files, Firefox did not warn the user that these files may contain malicious code.
    This vulnerability affects Firefox < 115, Firefox ESR < 102.13, and Thunderbird < 102.13. (CVE-2023-37208)

  - Memory safety bugs present in Firefox 114, Firefox ESR 102.12, and Thunderbird 102.12. Some of these bugs
    showed evidence of memory corruption and we presume that with enough effort some of these could have been
    exploited to run arbitrary code. This vulnerability affects Firefox < 115, Firefox ESR < 102.13, and
    Thunderbird < 102.13. (CVE-2023-37211)

  - The signature of a digitally signed S/MIME email message may optionally specify the signature creation
    date and time. If present, Thunderbird did not compare the signature creation date with the message date
    and time, and displayed a valid signature despite a date or time mismatch. This could be used to give
    recipients the impression that a message was sent at a different date or time. This vulnerability affects
    Thunderbird < 115.6. (CVE-2023-50761)

  - When processing a PGP/MIME payload that contains digitally signed text, the first paragraph of the text
    was never shown to the user. This is because the text was interpreted as a MIME message and the first
    paragraph was always treated as an email header section. A digitally signed text from a different context,
    such as a signed GIT commit, could be used to spoof an email message. This vulnerability affects
    Thunderbird < 115.6. (CVE-2023-50762)

  - An out of bounds write in ANGLE could have allowed an attacker to corrupt memory leading to a potentially
    exploitable crash. This vulnerability affects Firefox < 122, Firefox ESR < 115.7, and Thunderbird < 115.7.
    (CVE-2024-0741)

  - It was possible for certain browser prompts and dialogs to be activated or dismissed unintentionally by
    the user due to an incorrect timestamp used to prevent input after page load. This vulnerability affects
    Firefox < 122, Firefox ESR < 115.7, and Thunderbird < 115.7. (CVE-2024-0742)

  - A Linux user opening the print preview dialog could have caused the browser to crash. This vulnerability
    affects Firefox < 122, Firefox ESR < 115.7, and Thunderbird < 115.7. (CVE-2024-0746)

  - When a parent page loaded a child in an iframe with `unsafe-inline`, the parent Content Security Policy
    could have overridden the child Content Security Policy. This vulnerability affects Firefox < 122, Firefox
    ESR < 115.7, and Thunderbird < 115.7. (CVE-2024-0747)

  - A phishing site could have repurposed an `about:` dialog to show phishing content with an incorrect origin
    in the address bar. This vulnerability affects Firefox < 122 and Thunderbird < 115.7. (CVE-2024-0749)

  - A bug in popup notifications delay calculation could have made it possible for an attacker to trick a user
    into granting permissions. This vulnerability affects Firefox < 122, Firefox ESR < 115.7, and Thunderbird
    < 115.7. (CVE-2024-0750)

  - A malicious devtools extension could have been used to escalate privileges. This vulnerability affects
    Firefox < 122, Firefox ESR < 115.7, and Thunderbird < 115.7. (CVE-2024-0751)

  - In specific HSTS configurations an attacker could have bypassed HSTS on a subdomain. This vulnerability
    affects Firefox < 122, Firefox ESR < 115.7, and Thunderbird < 115.7. (CVE-2024-0753)

  - Memory safety bugs present in Firefox 121, Firefox ESR 115.6, and Thunderbird 115.6. Some of these bugs
    showed evidence of memory corruption and we presume that with enough effort some of these could have been
    exploited to run arbitrary code. This vulnerability affects Firefox < 122, Firefox ESR < 115.7, and
    Thunderbird < 115.7. (CVE-2024-0755)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202402-25");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=918444");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=920508");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=924845");
  script_set_attribute(attribute:"solution", value:
"All Mozilla Thunderbird binary users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=mail-client/thunderbird-bin-115.7.0
        
All Mozilla Thunderbird users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=mail-client/thunderbird-115.7.0");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-0755");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-5730");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/07/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:thunderbird-bin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gentoo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Gentoo/release", "Host/Gentoo/qpkg-list");

  exit(0);
}
include('qpkg.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/Gentoo/release')) audit(AUDIT_OS_NOT, 'Gentoo');
if (!get_kb_item('Host/Gentoo/qpkg-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var flag = 0;

var packages = [
  {
    'name' : 'mail-client/thunderbird',
    'unaffected' : make_list("ge 115.7.0"),
    'vulnerable' : make_list("lt 115.7.0")
  },
  {
    'name' : 'mail-client/thunderbird-bin',
    'unaffected' : make_list("ge 115.7.0"),
    'vulnerable' : make_list("lt 115.7.0")
  }
];

foreach var package( packages ) {
  if (isnull(package['unaffected'])) package['unaffected'] = make_list();
  if (isnull(package['vulnerable'])) package['vulnerable'] = make_list();
  if (qpkg_check(package: package['name'] , unaffected: package['unaffected'], vulnerable: package['vulnerable'])) flag++;
}


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : qpkg_report_get()
  );
  exit(0);
}
else
{
  qpkg_tests = list_uniq(qpkg_tests);
  var tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Mozilla Thunderbird');
}
