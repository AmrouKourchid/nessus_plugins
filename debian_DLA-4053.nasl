#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-4053. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(216351);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/15");

  script_cve_id(
    "CVE-2021-41160",
    "CVE-2022-24883",
    "CVE-2022-39282",
    "CVE-2022-39283",
    "CVE-2022-39316",
    "CVE-2022-39318",
    "CVE-2022-39319",
    "CVE-2022-39347",
    "CVE-2022-41877",
    "CVE-2023-39283",
    "CVE-2023-39350",
    "CVE-2023-39351",
    "CVE-2023-39352",
    "CVE-2023-39353",
    "CVE-2023-39354",
    "CVE-2023-39355",
    "CVE-2023-39356",
    "CVE-2023-40181",
    "CVE-2023-40186",
    "CVE-2023-40188",
    "CVE-2023-40567",
    "CVE-2023-40569",
    "CVE-2023-40589",
    "CVE-2024-22211",
    "CVE-2024-32039",
    "CVE-2024-32040",
    "CVE-2024-32458",
    "CVE-2024-32459",
    "CVE-2024-32460",
    "CVE-2024-32658",
    "CVE-2024-32659",
    "CVE-2024-32660",
    "CVE-2024-32661"
  );

  script_name(english:"Debian dla-4053 : freerdp2-dev - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-4053 advisory.

    -------------------------------------------------------------------------
    Debian LTS Advisory DLA-4053-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                         Tobias Frost
    February 15, 2025                             https://wiki.debian.org/LTS
    -------------------------------------------------------------------------

    Package        : freerdp2
    Version        : 2.3.0+dfsg1-2+deb11u2
    CVE ID         : CVE-2021-41160 CVE-2022-24883 CVE-2022-39282 CVE-2022-39283
                     CVE-2022-39316 CVE-2022-39318 CVE-2022-39319 CVE-2022-39347
                     CVE-2022-41877 CVE-2023-39350 CVE-2023-39351 CVE-2023-39352
                     CVE-2023-39353 CVE-2023-39354 CVE-2023-39356 CVE-2023-40181
                     CVE-2023-40186 CVE-2023-40188 CVE-2023-40567 CVE-2023-40569
                     CVE-2023-40589 CVE-2024-22211 CVE-2024-32039 CVE-2024-32040
                     CVE-2024-32458 CVE-2024-32459 CVE-2024-32460 CVE-2024-32658
                     CVE-2024-32659 CVE-2024-32660 CVE-2024-32661
    Debian Bug     : 1001062 1021659 1051638 1061173 1069728 1072112

    Multiple vulnerabilties have been found in freelrdp2, a free
    implementation of the Remote Desktop Protocol (RDP). The vulnerabilties
    potentially allows authentication bypasses on configuration errors,
    buffer overreads, DoS vectors, buffer overflows or accessing files
    outside of a shared directory.

    CVE-2021-41160

        In affected versions a malicious server might trigger out of bound
        writes in a connected client. Connections using GDI or SurfaceCommands
        to send graphics updates to the client might send `0` width/height or
        out of bound rectangles to trigger out of bound writes. With `0` width
        or heigth the memory allocation will be `0` but the missing bounds
        checks allow writing to the pointer at this (not allocated) region.

    CVE-2022-24883

        Prior to version 2.7.0, server side authentication against a `SAM` file
        might be successful for invalid credentials if the server has configured
        an invalid `SAM` file path. FreeRDP based clients are not affected. RDP
        server implementations using FreeRDP to authenticate against a `SAM`
        file are affected. Version 2.7.0 contains a fix for this issue. As a
        workaround, use custom authentication via `HashCallback` and/or ensure
        the `SAM` database path configured is valid and the application has file
        handles left.

    CVE-2022-39282

        FreeRDP based clients on unix systems using `/parallel` command line
        switch might read uninitialized data and send it to the server the
        client is currently connected to. FreeRDP based server implementations
        are not affected.

    CVE-2023-39283

        All FreeRDP based clients when using the `/video` command line switch
        might read uninitialized data, decode it as audio/video and display the
        result.  FreeRDP based server implementations are not affected.

    CVE-2022-39316

        In affected versions there is an out of bound read in ZGFX decoder
        component of FreeRDP. A malicious server can trick a FreeRDP based
        client to read out of bound data and try to decode it likely resulting
        in a crash.

    CVE-2022-39318

        Affected versions of FreeRDP are missing input validation in `urbdrc`
        channel.  A malicious server can trick a FreeRDP based client to crash
        with division by zero.

    CVE-2022-39319

        Affected versions of FreeRDP are missing input length validation in the
        `urbdrc` channel. A malicious server can trick a FreeRDP based client to
        read out of bound data and send it back to the server.

    CVE-2022-39347

        Affected versions of FreeRDP are missing path canonicalization and base
        path check for `drive` channel. A malicious server can trick a FreeRDP
        based client to read files outside the shared directory.

    CVE-2022-41877

        Affected versions of FreeRDP are missing input length validation in
        `drive` channel. A malicious server can trick a FreeRDP based client to
        read out of bound data and send it back to the server.

    CVE-2023-39350

        FreeRDP is a free implementation of the Remote Desktop Protocol (RDP),
        released under the Apache license. This issue affects Clients only.
        Integer underflow leading to DOS (e.g. abort due to `WINPR_ASSERT` with
        default compilation flags). When an insufficient blockLen is provided,
        and proper length validation is not performed, an Integer Underflow
        occurs, leading to a Denial of Service (DOS) vulnerability. This issue
        has been addressed in versions 2.11.0 and 3.0.0-beta3. Users are advised
        to upgrade. There are no known workarounds for this vulnerability.

    CVE-2023-39351

        FreeRDP is a free implementation of the Remote Desktop Protocol (RDP),
        released under the Apache license. Affected versions of FreeRDP are
        subject to a Null Pointer Dereference leading a crash in the RemoteFX
        (rfx) handling. Inside the `rfx_process_message_tileset` function, the
        program allocates tiles using `rfx_allocate_tiles` for the number of
        numTiles. If the initialization process of tiles is not completed for
        various reasons, tiles will have a NULL pointer. Which may be accessed
        in further processing and would cause a program crash. This issue has
        been addressed in versions 2.11.0 and 3.0.0-beta3. Users are advised to
        upgrade. There are no known workarounds for this vulnerability.

    CVE-2023-39352

        FreeRDP is a free implementation of the Remote Desktop Protocol (RDP),
        released under the Apache license. Affected versions are subject to an
        invalid offset validation leading to Out Of Bound Write. This can be
        triggered when the values `rect->left` and `rect->top` are exactly equal
        to `surface->width` and `surface->height`. eg. `rect->left` ==
        `surface->width` && `rect->top` == `surface->height`. In practice this
        should cause a crash. This issue has been addressed in versions 2.11.0
        and 3.0.0-beta3. Users are advised to upgrade. There are no known
        workarounds for this vulnerability.

    CVE-2023-39353

        FreeRDP is a free implementation of the Remote Desktop Protocol (RDP),
        released under the Apache license. Affected versions are subject to a
        missing offset validation leading to Out Of Bound Read.  In the
        `libfreerdp/codec/rfx.c` file there is no offset validation in
        `tile->quantIdxY`, `tile->quantIdxCb`, and `tile->quantIdxCr`. As a
        result crafted input can lead to an out of bounds read access which in
        turn will cause a crash. This issue has been addressed in versions
        2.11.0 and 3.0.0-beta3. Users are advised to upgrade. There are no known
        workarounds for this vulnerability.

    CVE-2023-39354

        FreeRDP is a free implementation of the Remote Desktop Protocol (RDP),
        released under the Apache license. Affected versions are subject to an
        Out-Of-Bounds Read in the `nsc_rle_decompress_data` function. The
        Out-Of-Bounds Read occurs because it processes `context->Planes` without
        checking if it contains data of sufficient length. Should an attacker be
        able to leverage this vulnerability they may be able to cause a crash.
        This issue has been addressed in versions 2.11.0 and 3.0.0-beta3. Users
        are advised to upgrade. There are no known workarounds for this
        vulnerability.

    CVE-2023-39355

        FreeRDP is a free implementation of the Remote Desktop Protocol (RDP),
        released under the Apache license. Versions of FreeRDP on the 3.x
        release branch before beta3 are subject to a Use-After-Free in
        processing `RDPGFX_CMDID_RESETGRAPHICS` packets. If
        `context->maxPlaneSize` is 0, `context->planesBuffer` will be freed.
        However, without updating `context->planesBuffer`, this leads to a
        Use-After-Free exploit vector. In most environments this should only
        result in a crash. This issue has been addressed in version 3.0.0-beta3
        and users of the beta 3.x releases are advised to upgrade. There are no
        known workarounds for this vulnerability.

    CVE-2023-39356

        FreeRDP is a free implementation of the Remote Desktop Protocol (RDP),
        released under the Apache license. In affected versions a missing offset
        validation may lead to an Out Of Bound Read in the function
        `gdi_multi_opaque_rect`. In particular there is no code to validate if
        the value `multi_opaque_rect->numRectangles` is less than 45. Looping
        through `multi_opaque_rect->`numRectangles without proper boundary
        checks can lead to Out-of-Bounds Read errors which will likely lead to a
        crash. This issue has been addressed in versions 2.11.0 and 3.0.0-beta3.
        Users are advised to upgrade. There are no known workarounds for this
        vulnerability.

    CVE-2023-40181

        FreeRDP is a free implementation of the Remote Desktop Protocol (RDP),
        released under the Apache license. Affected versions are subject to an
        Integer-Underflow leading to Out-Of-Bound Read in the
        `zgfx_decompress_segment` function. In the context of `CopyMemory`, it's
        possible to read data beyond the transmitted packet range and likely
        cause a crash. This issue has been addressed in versions 2.11.0 and
        3.0.0-beta3. Users are advised to upgrade. There are no known
        workarounds for this issue.

    CVE-2023-40186

        FreeRDP is a free implementation of the Remote Desktop Protocol (RDP),
        released under the Apache license. Affected versions are subject to an
        IntegerOverflow leading to Out-Of-Bound Write Vulnerability in the
        `gdi_CreateSurface` function. This issue affects FreeRDP based clients
        only. FreeRDP proxies are not affected as image decoding is not done by
        a proxy. This issue has been addressed in versions 2.11.0 and
        3.0.0-beta3. Users are advised to upgrade. There are no known
        workarounds for this issue.

    CVE-2023-40188

        FreeRDP is a free implementation of the Remote Desktop Protocol (RDP),
        released under the Apache license. Affected versions are subject to an
        Out-Of-Bounds Read in the `general_LumaToYUV444` function. This
        Out-Of-Bounds Read occurs because processing is done on the `in`
        variable without checking if it contains data of sufficient length.
        Insufficient data for the `in` variable may cause errors or crashes.
        This issue has been addressed in versions 2.11.0 and 3.0.0-beta3. Users
        are advised to upgrade. There are no known workarounds for this issue.

    CVE-2023-40567

        FreeRDP is a free implementation of the Remote Desktop Protocol (RDP),
        released under the Apache license. Affected versions are subject to an
        Out-Of-Bounds Write in the `clear_decompress_bands_data` function in
        which there is no offset validation. Abuse of this vulnerability may
        lead to an out of bounds write. This issue has been addressed in
        versions 2.11.0 and 3.0.0-beta3. Users are advised to upgrade. there are
        no known workarounds for this vulnerability.

    CVE-2023-40569

        FreeRDP is a free implementation of the Remote Desktop Protocol (RDP),
        released under the Apache license. Affected versions are subject to an
        Out-Of-Bounds Write in the `progressive_decompress` function. This issue
        is likely down to incorrect calculations of the `nXSrc` and `nYSrc`
        variables. This issue has been addressed in versions 2.11.0 and
        3.0.0-beta3. Users are advised to upgrade. there are no known
        workarounds for this vulnerability.

    CVE-2023-40589

        FreeRDP is a free implementation of the Remote Desktop Protocol (RDP),
        released under the Apache license. In affected versions there is a
        Global-Buffer-Overflow in the ncrush_decompress function.  Feeding
        crafted input into this function can trigger the overflow which has only
        been shown to cause a crash. This issue has been addressed in versions
        2.11.0 and 3.0.0-beta3. Users are advised to upgrade. There are no known
        workarounds for this issue.

    CVE-2024-22211

        FreeRDP is a set of free and open source remote desktop protocol library
        and clients. In affected versions an integer overflow in
        `freerdp_bitmap_planar_context_reset` leads to heap-buffer overflow.
        This affects FreeRDP based clients. FreeRDP based server implementations
        and proxy are not affected. A malicious server could prepare a
        `RDPGFX_RESET_GRAPHICS_PDU` to allocate too small buffers, possibly
        triggering later out of bound read/write. Data extraction over network
        is not possible, the buffers are used to display an image. This issue
        has been addressed in version 2.11.5 and 3.2.0. Users are advised to
        upgrade. there are no know workarounds for this vulnerability.

    CVE-2024-32039

        FreeRDP is a free implementation of the Remote Desktop Protocol. FreeRDP
        based clients using a version of FreeRDP prior to 3.5.0 or 2.11.6 are
        vulnerable to integer overflow and out-of-bounds write. Versions 3.5.0
        and 2.11.6 patch the issue. As a workaround, do not use `/gfx` options
        (e.g. deactivate with `/bpp:32` or `/rfx` as it is on by default).

    CVE-2024-32040

        FreeRDP is a free implementation of the Remote Desktop Protocol. FreeRDP
        based clients that use a version of FreeRDP prior to 3.5.0 or 2.11.6 and
        have connections to servers using the `NSC` codec are vulnerable to
        integer underflow. Versions 3.5.0 and 2.11.6 patch the issue. As a
        workaround, do not use the NSC codec (e.g. use `-nsc`).

    CVE-2024-32458

        FreeRDP is a free implementation of the Remote Desktop Protocol. FreeRDP
        based clients that use a version of FreeRDP prior to 3.5.0 or 2.11.6 are
        vulnerable to out-of-bounds read. Versions 3.5.0 and 2.11.6 patch the
        issue. As a workaround, use `/gfx` or `/rfx` modes (on by default,
        require server side support).

    CVE-2024-32459

        FreeRDP is a free implementation of the Remote Desktop Protocol. FreeRDP
        based clients and servers that use a version of FreeRDP prior to 3.5.0
        or 2.11.6 are vulnerable to out-of-bounds read. Versions 3.5.0 and
        2.11.6 patch the issue. No known workarounds are available.

    CVE-2024-32460

        FreeRDP is a free implementation of the Remote Desktop Protocol. FreeRDP
        based based clients using `/bpp:32` legacy `GDI` drawing path with a
        version of FreeRDP prior to 3.5.0 or 2.11.6 are vulnerable to
        out-of-bounds read. Versions 3.5.0 and 2.11.6 patch the issue. As a
        workaround, use modern drawing paths (e.g. `/rfx` or `/gfx` options).
        The workaround requires server side support.

    CVE-2024-32658

        FreeRDP is a free implementation of the Remote Desktop Protocol. FreeRDP
        based clients prior to version 3.5.1 are vulnerable to out-of-bounds
        read. Version 3.5.1 contains a patch for the issue. No known workarounds
        are available.

    CVE-2024-32659

        FreeRDP is a free implementation of the Remote Desktop Protocol. FreeRDP
        based clients prior to version 3.5.1 are vulnerable to out-of-bounds
        read if `((nWidth == 0) and (nHeight == 0))`. Version 3.5.1 contains a
        patch for the issue. No known workarounds are available.

    CVE-2024-32660

        FreeRDP is a free implementation of the Remote Desktop Protocol. Prior
        to version 3.5.1, a malicious server can crash the FreeRDP client by
        sending invalid huge allocation size. Version 3.5.1 contains a patch for
        the issue. No known workarounds are available.

    CVE-2024-32661

        FreeRDP is a free implementation of the Remote Desktop Protocol. FreeRDP
        based clients prior to version 3.5.1 are vulnerable to a possible `NULL`
        access and crash. Version 3.5.1 contains a patch for the issue. No known
        workarounds are available.

    For Debian 11 bullseye, these problems have been fixed in version
    2.3.0+dfsg1-2+deb11u2.

    We recommend that you upgrade your freerdp2 packages.

    For the detailed security status of freerdp2 please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/freerdp2

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS
    Attachment:
    signature.asc
    Description: PGP signature

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/freerdp2");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-41160");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-24883");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-39282");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-39283");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-39316");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-39318");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-39319");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-39347");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-41877");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-39283");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-39350");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-39351");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-39352");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-39353");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-39354");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-39355");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-39356");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-40181");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-40186");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-40188");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-40567");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-40569");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-40589");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-22211");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-32039");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-32040");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-32458");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-32459");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-32460");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-32658");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-32659");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-32660");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-32661");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/freerdp2");
  script_set_attribute(attribute:"solution", value:
"Upgrade the freerdp2-dev packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-24883");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-32659");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/02/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:freerdp2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:freerdp2-shadow-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:freerdp2-wayland");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:freerdp2-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libfreerdp-client2-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libfreerdp-server2-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libfreerdp-shadow-subsystem2-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libfreerdp-shadow2-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libfreerdp2-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libuwac0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libuwac0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwinpr-tools2-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwinpr2-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwinpr2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:winpr-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var debian_release = get_kb_item('Host/Debian/release');
if ( isnull(debian_release) ) audit(AUDIT_OS_NOT, 'Debian');
debian_release = chomp(debian_release);
if (! preg(pattern:"^(11)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 11.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '11.0', 'prefix': 'freerdp2-dev', 'reference': '2.3.0+dfsg1-2+deb11u2'},
    {'release': '11.0', 'prefix': 'freerdp2-shadow-x11', 'reference': '2.3.0+dfsg1-2+deb11u2'},
    {'release': '11.0', 'prefix': 'freerdp2-wayland', 'reference': '2.3.0+dfsg1-2+deb11u2'},
    {'release': '11.0', 'prefix': 'freerdp2-x11', 'reference': '2.3.0+dfsg1-2+deb11u2'},
    {'release': '11.0', 'prefix': 'libfreerdp-client2-2', 'reference': '2.3.0+dfsg1-2+deb11u2'},
    {'release': '11.0', 'prefix': 'libfreerdp-server2-2', 'reference': '2.3.0+dfsg1-2+deb11u2'},
    {'release': '11.0', 'prefix': 'libfreerdp-shadow-subsystem2-2', 'reference': '2.3.0+dfsg1-2+deb11u2'},
    {'release': '11.0', 'prefix': 'libfreerdp-shadow2-2', 'reference': '2.3.0+dfsg1-2+deb11u2'},
    {'release': '11.0', 'prefix': 'libfreerdp2-2', 'reference': '2.3.0+dfsg1-2+deb11u2'},
    {'release': '11.0', 'prefix': 'libuwac0-0', 'reference': '2.3.0+dfsg1-2+deb11u2'},
    {'release': '11.0', 'prefix': 'libuwac0-dev', 'reference': '2.3.0+dfsg1-2+deb11u2'},
    {'release': '11.0', 'prefix': 'libwinpr-tools2-2', 'reference': '2.3.0+dfsg1-2+deb11u2'},
    {'release': '11.0', 'prefix': 'libwinpr2-2', 'reference': '2.3.0+dfsg1-2+deb11u2'},
    {'release': '11.0', 'prefix': 'libwinpr2-dev', 'reference': '2.3.0+dfsg1-2+deb11u2'},
    {'release': '11.0', 'prefix': 'winpr-utils', 'reference': '2.3.0+dfsg1-2+deb11u2'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var _release = NULL;
  var prefix = NULL;
  var reference = NULL;
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['prefix'])) prefix = package_array['prefix'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (_release && prefix && reference) {
    if (deb_check(release:_release, prefix:prefix, reference:reference)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'freerdp2-dev / freerdp2-shadow-x11 / freerdp2-wayland / freerdp2-x11 / etc');
}
