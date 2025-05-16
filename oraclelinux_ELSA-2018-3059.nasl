#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2018-3059.
##

include('compat.inc');

if (description)
{
  script_id(181044);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/01");

  script_cve_id("CVE-2015-9262");

  script_name(english:"Oracle Linux 7 : X.org / X11 (ELSA-2018-3059)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 7 host has packages installed that are affected by a vulnerability as referenced in the
ELSA-2018-3059 advisory.

    freeglut
    [3.0.0-8]
    - HTTPS URLs
    - Pin soname to libglut.so.3 in the %files glob

    [3.0.0-7]
    - Rebuilt for https://fedoraproject.org/wiki/Fedora_28_Mass_Rebuild

    [3.0.0-6]
    - Rebuilt for https://fedoraproject.org/wiki/Fedora_27_Binutils_Mass_Rebuild

    [3.0.0-5]
    - Rebuilt for https://fedoraproject.org/wiki/Fedora_27_Mass_Rebuild

    [3.0.0-4]
    - Rebuilt for https://fedoraproject.org/wiki/Fedora_26_Mass_Rebuild

    [3.0.0-3]
    - Rebuilt for https://fedoraproject.org/wiki/Fedora_24_Mass_Rebuild

    [3.0.0-2]
    - Rebuilt for https://fedoraproject.org/wiki/Fedora_23_Mass_Rebuild

    [3.0.0-1]
    - New upstream version

    [2.8.1-5]
    - Rebuilt for https://fedoraproject.org/wiki/Fedora_21_22_Mass_Rebuild

    [2.8.1-4]
    - Rebuilt for https://fedoraproject.org/wiki/Fedora_21_Mass_Rebuild

    libX11
    [1.6.5-2]
    - Rebuild to pick up new xproto keysyms (#1600147)

    libXcursor
    [1.1.15-1]
    - libXcursor 1.1.15

    libXfont
    [1.5.4-1]
    - libXfont 1.5.4.

    libXfont2
    [2.0.3-1]
    - libXfont 2.0.3

    libXres
    [1.2.0-1]
    - libXres 1.2.0

    libdrm
    [2.4.91-3]
    - Add WHL, AML, etc PCI IDs

    [2.4.91-2]
    - libdrm 2.4.91

    libepoxy
    [1.5.2-1]
    - epoxy 1.5.2

    libglvnd
    [1.0.1-0.8.git5baa1e5]
    - rename fallback from fedora to system

    [1.0.1-0.7.git5baa1e5]
    - Add another fallback GLX library name

    [1.0.1-0.6.git5baa1e5]
    - Enable %check for all but ppc64 and s390x, which has known but low-impact
      failures
    - Simplify %release

    [1.0.1-0.5.20180327git5baa1e5]
    - Go back to Requires: mesa-*, the fallout is too great (#1568881 etc)

    [1:1.0.1-0.4.20180327git5baa1e5]
    - Update snapshot to 20180327

    [1.0.1-0.3.20180226gitb029c24]
    - Use Recommends: mesa-* not Requires.
    - (Trivially) switch the build to python3

    [1:1.0.1-0.2.20180226gitb029c24]
    - Update Python 2 dependency declarations to new packaging standards
      (See https://fedoraproject.org/wiki/FinalizingFedoraSwitchtoPython3)

    [1:1.0.1-0.1.20180226gitb029c24]
    - Update snapshot to 20180226
    - Update scriptlets

    libinput
    [1.10.7-2]
    - Correct the automake version number to 1.10.7 (#1564642)

    [1.10.7-1]
    - libinput 1.10.7 (#1564642)

    libwacom
    [0.30-1]
    - libwacom 0.30 (#1564606)

    libxcb
    [1.13-1]
    - libxcb 1.13

    mesa
    [18.0.5-3]
    - rename fedora to system in glvnd fallback

    [18.0.5-2]
    - Fix timeout overflow warnings (backport from upstream + virgl)

    [18.0.5-1]
    - Mesa 18.0.5

    [18.0.4-1.20180530]
    - rebase to 18.0.4
    - backport shm put/get image for improved sw renderers (esp under qxl)

    [18.0.3-5.20180508]
    - Fix gl.pc when using glvnd
    - Fix subpackage dependencies for glvnd

    [18.0.3-2.20180508]
    - Use glvnd

    [18.0.3-1.20180508]
    - rebase to 18.0.3

    mesa-demos
    [8.3.0-10]
    - Rebuilt for https://fedoraproject.org/wiki/Fedora_28_Mass_Rebuild

    [8.3.0-9]
    - New git snapshot

    [8.3.0-8]
    - Rebuilt for https://fedoraproject.org/wiki/Fedora_27_Binutils_Mass_Rebuild

    [8.3.0-7]
    - Rebuilt for https://fedoraproject.org/wiki/Fedora_27_Mass_Rebuild

    [8.3.0-6]
    - Fix xdriinfo not working with libglvnd (rhbz#1429894)

    [8.3.0-5]
    - Rebuilt for https://fedoraproject.org/wiki/Fedora_26_Mass_Rebuild

    [8.3.0-4]
    - Rebuild for glew 2.0.0

    [8.3.0-3]
    - Rebuilt for https://fedoraproject.org/wiki/Fedora_24_Mass_Rebuild

    [8.3.0-2]
    - Rebuild for glew 1.13

    [8.3.0-1]
    - 8.3.0

    [8.2.0-5]
    - New git snap
    - Add EGL/GLES buildreqs and egl-utils subpackage

    [8.2.0-4]
    - Rebuilt for https://fedoraproject.org/wiki/Fedora_23_Mass_Rebuild

    tigervnc
    [1.8.0-13]
    - Add one remaining option to Xvnc manpage
      Resolves: bz#1601880

    [1.8.0-12]
    - Add missing options to Xvnc manpage
      Resolves: bz#1601880

    [1.8.0-11]
    - Properly kill session after user logs out
      Resolves: bz#1259757

    [1.8.0-10]
    - Check endianness when constructing platform pixel buffer
      Resolves: bz#1613264

    [1.8.0-9]
    - Use current server time for XUngrabPointer and XUngrabKeyboard
      Resolves: bz#1605325

    [1.8.0-8]
    - Ignore fake focus events from XGrabKeyboard()
      Resolves: bz#1602855

    [1.8.0-7]
    Properly support Xorg 1.20
      Resolves: bz#1564061

    [1.8.0-6]
    - Kill session after user logs out
      Resolves: bz#1259757

      Build against Xorg 1.20
      Resolves: bz#1564061

    vulkan
    [1.1.73.0-1]
    - Update to 1.1.73.0 release
    - fixup spec for spirv-tools etc

    xcb-proto
    [1.13-1]
    - xcb-proto 1.13

    [1.12-6]
    - Rebuilt for https://fedoraproject.org/wiki/Fedora_28_Mass_Rebuild

    [1.12-5]
    - Add a build-time dependency on python2-devel

    [1.12-4]
    - Rebuilt for https://fedoraproject.org/wiki/Fedora_27_Mass_Rebuild

    [1.12-3]
    - Rebuilt for https://fedoraproject.org/wiki/Fedora_26_Mass_Rebuild

    xkeyboard-config
    [2.24-1]
    - xkeyboard-config 2.24 (#1564615)
    - Revert the high-keycode patches to avoid conflicts with xkbcomp < 1.4

    [2.23.1-1]
    - xkeyboard-config 2.23.1 (#1564615)

    xorg-x11-drv-ati
    [18.0.1-1]
    - ati 18.0.1

    xorg-x11-drv-dummy
    [0.3.7-1.1]
    - Rebuild for xserver 1.20

    xorg-x11-drv-evdev
    [2.10.6-1]
    - evdev 2.10.6 (#1564618)

    xorg-x11-drv-fbdev
    [0.5.0-1]
    - fbdev 0.5.0

    [0.4.3-25.1]
    - Rebuild for xserver 1.20

    xorg-x11-drv-intel
    [2.99.917-28]
    - Today's git snapshot (commit 35947721)

    xorg-x11-drv-libinput
    [0.27.1-2]
    - Fix invalid-sized memset() in the draglock code

    [0.27.1-1]
    - libinput 0.27.1 (#1564643)

    xorg-x11-drv-mouse
    [1.9.2-2]
    - Avoid use of xf86GetOS (#1592607)

    xorg-x11-drv-nouveau
    [1.0.15-1]
    - nouveau 1.0.15

    [1:1.0.13-3.1]
    - Rebuild for xserver 1.20

    xorg-x11-drv-openchrome
    [0.5.0-3.1]
    - Rebuild for xserver 1.20

    xorg-x11-drv-qxl
    [0.1.5-4.1]
    - Rebuild for xserver 1.20

    [0.1.5-4]
    - Fix crash when multiple QXL devices are in use
      Resolves: rhbz#1428340

    xorg-x11-drv-synaptics
    [1.9.0-2]
    - Fix infinite log spam in case of read errors (#1564624).

    xorg-x11-drv-v4l
    [0.2.0-49]
    - Remove call to LoaderGetOS - Patch wasn't applied (#1601960)

    [0.2.0-48]
    - Remove call to LoaderGetOS (#1601960)

    xorg-x11-drv-vesa
    [2.4.0-1]
    - vesa 2.4.0

    [2.3.2-25.1.1]
    - Rebuild for xserver 1.20

    xorg-x11-drv-vmmouse
    [13.1.0-1.1]
    - Rebuild for xserver 1.20

    xorg-x11-drv-vmware
    [13.2.1-1.1]
    - Rebuild for xserver 1.20

    xorg-x11-drv-void
    [1.4.1-2.1]
    - Rebuild for xserver 1.20

    xorg-x11-drv-wacom
    [0.36.1-1]
    - wacom 0.36.1 (#1564630)

    xorg-x11-font-utils
    [1:7.5-21]
    - Rebase to F28 (#1564630)

    xorg-x11-proto-devel
    [2018.4-1]
    - xorgproto 2018.4

    [2018.3-1]
    - xorgproto 2018.3

    [2018.2-1]
    - xorgproto 2018.2

    [2018.1-2]
    - Rebuilt for https://fedoraproject.org/wiki/Fedora_28_Mass_Rebuild

    [2018.1-1]
    - Switch to merged protocol headers
    - Drop evie headers
    - Pre-F18 changelog trim

    [7.7-24]
    - Drop bootstrap hack (that had been enabled for like nine years anyway)
    - Use https URLs

    [7.7-23]
    - Rebuilt for https://fedoraproject.org/wiki/Fedora_27_Mass_Rebuild

    [7.7-22]
    - Add xproto patches from upstream adding XF86Keyboard and XF86RFKill keysyms

    [7.7-21]
    - Rebuilt for https://fedoraproject.org/wiki/Fedora_26_Mass_Rebuild

    xorg-x11-server
    [1.20.1-3]
    - Try harder to come up with an initial spanning configuration

    [1.20.1-2]
    - Make platform device probe a bit less fragile
    - Disable glamor on llvmpipe

    [1.20.1-1]
    - xserver 1.20.1
    - Enable backing store's Always mode

    [1.20.0-2]
    - Fix glx vendor hash table key size
    - Fix memory corruption during PanoramiX setup (#1601742)

    [1.20.0-1]
    - Fix 16bpp with modesetting driver

    [1.20.0-0.3]
    - Add patches for bz1591978

    [1.20.0-0.2]
    - Add patches for bz1585252

    [1.20.0-0.1]
    - Initial 1.20 rebuild

    xorg-x11-utils
    [7.5-23]
    - xlsclients 1.1.4
    - xlsfonts 1.0.6
    - xprop 1.2.3
    - HTTPS URLs

    xorg-x11-xkb-utils
    [7.7-14]
    - xkbcomp 1.4.2 (#1564634)

    [7.7-13]
    - Sync with F28 (#1564634)
    - setxkbmap 1.3.1
    - xkbcomp 1.4.1
    - xkbevd 1.1.4
    - xkbprint 1.0.4

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2018-3059.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-9262");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:drm-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:egl-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:freeglut");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:freeglut-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glx-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:intel-gpu-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libX11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libX11-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libX11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libXcursor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libXcursor-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libXfont");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libXfont-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libXfont2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libXfont2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libXres");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libXres-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libdrm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libdrm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libepoxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libepoxy-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libglvnd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libglvnd-core-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libglvnd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libglvnd-egl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libglvnd-gles");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libglvnd-glx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libglvnd-opengl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libinput");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libinput-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libwacom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libwacom-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libwacom-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libxcb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libxcb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libxcb-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mesa-demos");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mesa-dri-drivers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mesa-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mesa-libEGL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mesa-libEGL-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mesa-libGL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mesa-libGL-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mesa-libGLES");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mesa-libGLES-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mesa-libOSMesa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mesa-libOSMesa-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mesa-libgbm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mesa-libgbm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mesa-libglapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mesa-libwayland-egl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mesa-libwayland-egl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mesa-libxatracker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mesa-libxatracker-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mesa-vdpau-drivers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mesa-vulkan-drivers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tigervnc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tigervnc-icons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tigervnc-license");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tigervnc-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tigervnc-server-applet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tigervnc-server-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tigervnc-server-module");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:vulkan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:vulkan-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:vulkan-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xcb-proto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xkeyboard-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xkeyboard-config-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-drv-ati");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-drv-dummy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-drv-evdev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-drv-evdev-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-drv-fbdev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-drv-intel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-drv-intel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-drv-libinput");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-drv-libinput-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-drv-mouse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-drv-mouse-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-drv-nouveau");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-drv-openchrome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-drv-openchrome-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-drv-qxl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-drv-synaptics");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-drv-synaptics-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-drv-v4l");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-drv-vesa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-drv-vmmouse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-drv-vmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-drv-void");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-drv-wacom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-drv-wacom-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-font-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-proto-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-server-Xdmx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-server-Xephyr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-server-Xnest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-server-Xorg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-server-Xspice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-server-Xvfb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-server-Xwayland");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-server-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-server-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-server-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-xkb-extras");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-xkb-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-xkb-utils-devel");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/OracleLinux')) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_release = get_kb_item("Host/RedHat/release");
if (isnull(os_release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:os_release)) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Oracle Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 7', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var pkgs = [
    {'reference':'drm-utils-2.4.91-3.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'egl-utils-8.3.0-10.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'freeglut-3.0.0-8.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'freeglut-devel-3.0.0-8.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glx-utils-8.3.0-10.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libX11-1.6.5-2.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libX11-common-1.6.5-2.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libX11-devel-1.6.5-2.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libXcursor-1.1.15-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libXcursor-devel-1.1.15-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libXfont-1.5.4-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libXfont-devel-1.5.4-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libXfont2-2.0.3-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libXfont2-devel-2.0.3-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libXres-1.2.0-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libXres-devel-1.2.0-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libdrm-2.4.91-3.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libdrm-devel-2.4.91-3.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libepoxy-1.5.2-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libepoxy-devel-1.5.2-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libglvnd-1.0.1-0.8.git5baa1e5.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libglvnd-core-devel-1.0.1-0.8.git5baa1e5.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libglvnd-devel-1.0.1-0.8.git5baa1e5.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libglvnd-egl-1.0.1-0.8.git5baa1e5.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libglvnd-gles-1.0.1-0.8.git5baa1e5.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libglvnd-glx-1.0.1-0.8.git5baa1e5.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libglvnd-opengl-1.0.1-0.8.git5baa1e5.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libinput-1.10.7-2.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libinput-devel-1.10.7-2.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libwacom-0.30-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libwacom-data-0.30-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libwacom-devel-0.30-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libxcb-1.13-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libxcb-devel-1.13-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libxcb-doc-1.13-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mesa-demos-8.3.0-10.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mesa-dri-drivers-18.0.5-3.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mesa-filesystem-18.0.5-3.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mesa-libEGL-18.0.5-3.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mesa-libEGL-devel-18.0.5-3.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mesa-libGL-18.0.5-3.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mesa-libGL-devel-18.0.5-3.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mesa-libGLES-18.0.5-3.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mesa-libGLES-devel-18.0.5-3.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mesa-libOSMesa-18.0.5-3.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mesa-libOSMesa-devel-18.0.5-3.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mesa-libgbm-18.0.5-3.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mesa-libgbm-devel-18.0.5-3.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mesa-libglapi-18.0.5-3.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mesa-libwayland-egl-18.0.5-3.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mesa-libwayland-egl-devel-18.0.5-3.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mesa-vdpau-drivers-18.0.5-3.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tigervnc-1.8.0-13.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tigervnc-icons-1.8.0-13.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tigervnc-license-1.8.0-13.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tigervnc-server-1.8.0-13.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tigervnc-server-applet-1.8.0-13.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tigervnc-server-minimal-1.8.0-13.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tigervnc-server-module-1.8.0-13.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vulkan-1.1.73.0-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vulkan-devel-1.1.73.0-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vulkan-filesystem-1.1.73.0-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xcb-proto-1.13-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xkeyboard-config-2.24-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xkeyboard-config-devel-2.24-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-drv-ati-18.0.1-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-drv-dummy-0.3.7-1.el7.1', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-drv-evdev-2.10.6-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-drv-evdev-devel-2.10.6-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-drv-fbdev-0.5.0-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-drv-libinput-0.27.1-2.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-drv-libinput-devel-0.27.1-2.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-drv-mouse-1.9.2-2.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-drv-mouse-devel-1.9.2-2.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-drv-nouveau-1.0.15-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'xorg-x11-drv-qxl-0.1.5-4.el7.1', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-drv-synaptics-1.9.0-2.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-drv-synaptics-devel-1.9.0-2.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-drv-v4l-0.2.0-49.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-drv-void-1.4.1-2.el7.1', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-drv-wacom-0.36.1-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-drv-wacom-devel-0.36.1-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-font-utils-7.5-21.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'xorg-x11-proto-devel-2018.4-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-server-Xdmx-1.20.1-3.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-server-Xephyr-1.20.1-3.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-server-Xnest-1.20.1-3.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-server-Xorg-1.20.1-3.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-server-Xvfb-1.20.1-3.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-server-Xwayland-1.20.1-3.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-server-common-1.20.1-3.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-server-devel-1.20.1-3.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-server-source-1.20.1-3.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-utils-7.5-23.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-xkb-extras-7.7-14.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-xkb-utils-7.7-14.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-xkb-utils-devel-7.7-14.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'freeglut-3.0.0-8.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'freeglut-devel-3.0.0-8.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glx-utils-8.3.0-10.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libX11-1.6.5-2.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libX11-common-1.6.5-2.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libX11-devel-1.6.5-2.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libXcursor-1.1.15-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libXcursor-devel-1.1.15-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libXfont-1.5.4-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libXfont-devel-1.5.4-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libXfont2-2.0.3-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libXfont2-devel-2.0.3-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libXres-1.2.0-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libXres-devel-1.2.0-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libdrm-2.4.91-3.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libdrm-devel-2.4.91-3.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libepoxy-1.5.2-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libepoxy-devel-1.5.2-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libglvnd-1.0.1-0.8.git5baa1e5.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libglvnd-core-devel-1.0.1-0.8.git5baa1e5.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libglvnd-devel-1.0.1-0.8.git5baa1e5.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libglvnd-egl-1.0.1-0.8.git5baa1e5.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libglvnd-gles-1.0.1-0.8.git5baa1e5.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libglvnd-glx-1.0.1-0.8.git5baa1e5.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libglvnd-opengl-1.0.1-0.8.git5baa1e5.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libinput-1.10.7-2.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libinput-devel-1.10.7-2.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libwacom-0.30-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libwacom-data-0.30-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libwacom-devel-0.30-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libxcb-1.13-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libxcb-devel-1.13-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libxcb-doc-1.13-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mesa-demos-8.3.0-10.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mesa-dri-drivers-18.0.5-3.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mesa-filesystem-18.0.5-3.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mesa-libEGL-18.0.5-3.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mesa-libEGL-devel-18.0.5-3.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mesa-libGL-18.0.5-3.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mesa-libGL-devel-18.0.5-3.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mesa-libGLES-18.0.5-3.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mesa-libGLES-devel-18.0.5-3.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mesa-libOSMesa-18.0.5-3.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mesa-libOSMesa-devel-18.0.5-3.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mesa-libgbm-18.0.5-3.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mesa-libgbm-devel-18.0.5-3.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mesa-libglapi-18.0.5-3.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mesa-libwayland-egl-18.0.5-3.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mesa-libwayland-egl-devel-18.0.5-3.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mesa-libxatracker-18.0.5-3.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mesa-libxatracker-devel-18.0.5-3.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mesa-vdpau-drivers-18.0.5-3.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mesa-vulkan-drivers-18.0.5-3.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tigervnc-1.8.0-13.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tigervnc-icons-1.8.0-13.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tigervnc-license-1.8.0-13.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tigervnc-server-1.8.0-13.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tigervnc-server-applet-1.8.0-13.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tigervnc-server-minimal-1.8.0-13.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tigervnc-server-module-1.8.0-13.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vulkan-1.1.73.0-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vulkan-devel-1.1.73.0-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vulkan-filesystem-1.1.73.0-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xcb-proto-1.13-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xkeyboard-config-2.24-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xkeyboard-config-devel-2.24-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-drv-ati-18.0.1-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-drv-dummy-0.3.7-1.el7.1', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-drv-evdev-2.10.6-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-drv-evdev-devel-2.10.6-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-drv-fbdev-0.5.0-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-drv-intel-2.99.917-28.20180530.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-drv-intel-devel-2.99.917-28.20180530.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-drv-libinput-0.27.1-2.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-drv-libinput-devel-0.27.1-2.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-drv-mouse-1.9.2-2.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-drv-mouse-devel-1.9.2-2.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-drv-nouveau-1.0.15-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'xorg-x11-drv-openchrome-0.5.0-3.el7.1', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-drv-openchrome-devel-0.5.0-3.el7.1', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-drv-qxl-0.1.5-4.el7.1', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-drv-synaptics-1.9.0-2.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-drv-synaptics-devel-1.9.0-2.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-drv-v4l-0.2.0-49.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-drv-vesa-2.4.0-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-drv-vmmouse-13.1.0-1.el7.1', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-drv-vmware-13.2.1-1.el7.1', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-drv-void-1.4.1-2.el7.1', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-drv-wacom-0.36.1-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-drv-wacom-devel-0.36.1-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-font-utils-7.5-21.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'xorg-x11-proto-devel-2018.4-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-server-Xdmx-1.20.1-3.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-server-Xephyr-1.20.1-3.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-server-Xnest-1.20.1-3.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-server-Xorg-1.20.1-3.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-server-Xspice-0.1.5-4.el7.1', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-server-Xvfb-1.20.1-3.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-server-Xwayland-1.20.1-3.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-server-common-1.20.1-3.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-server-devel-1.20.1-3.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-server-source-1.20.1-3.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-utils-7.5-23.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-xkb-extras-7.7-14.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-xkb-utils-7.7-14.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-xkb-utils-devel-7.7-14.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'drm-utils-2.4.91-3.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'egl-utils-8.3.0-10.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'freeglut-3.0.0-8.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'freeglut-devel-3.0.0-8.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glx-utils-8.3.0-10.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'intel-gpu-tools-2.99.917-28.20180530.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libX11-1.6.5-2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libX11-common-1.6.5-2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libX11-devel-1.6.5-2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libXcursor-1.1.15-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libXcursor-devel-1.1.15-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libXfont-1.5.4-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libXfont-devel-1.5.4-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libXfont2-2.0.3-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libXfont2-devel-2.0.3-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libXres-1.2.0-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libXres-devel-1.2.0-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libdrm-2.4.91-3.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libdrm-devel-2.4.91-3.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libepoxy-1.5.2-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libepoxy-devel-1.5.2-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libglvnd-1.0.1-0.8.git5baa1e5.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libglvnd-core-devel-1.0.1-0.8.git5baa1e5.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libglvnd-devel-1.0.1-0.8.git5baa1e5.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libglvnd-egl-1.0.1-0.8.git5baa1e5.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libglvnd-gles-1.0.1-0.8.git5baa1e5.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libglvnd-glx-1.0.1-0.8.git5baa1e5.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libglvnd-opengl-1.0.1-0.8.git5baa1e5.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libinput-1.10.7-2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libinput-devel-1.10.7-2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libwacom-0.30-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libwacom-data-0.30-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libwacom-devel-0.30-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libxcb-1.13-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libxcb-devel-1.13-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libxcb-doc-1.13-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mesa-demos-8.3.0-10.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mesa-dri-drivers-18.0.5-3.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mesa-filesystem-18.0.5-3.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mesa-libEGL-18.0.5-3.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mesa-libEGL-devel-18.0.5-3.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mesa-libGL-18.0.5-3.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mesa-libGL-devel-18.0.5-3.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mesa-libGLES-18.0.5-3.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mesa-libGLES-devel-18.0.5-3.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mesa-libOSMesa-18.0.5-3.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mesa-libOSMesa-devel-18.0.5-3.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mesa-libgbm-18.0.5-3.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mesa-libgbm-devel-18.0.5-3.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mesa-libglapi-18.0.5-3.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mesa-libwayland-egl-18.0.5-3.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mesa-libwayland-egl-devel-18.0.5-3.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mesa-libxatracker-18.0.5-3.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mesa-libxatracker-devel-18.0.5-3.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mesa-vdpau-drivers-18.0.5-3.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mesa-vulkan-drivers-18.0.5-3.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tigervnc-1.8.0-13.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tigervnc-icons-1.8.0-13.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tigervnc-license-1.8.0-13.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tigervnc-server-1.8.0-13.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tigervnc-server-applet-1.8.0-13.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tigervnc-server-minimal-1.8.0-13.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tigervnc-server-module-1.8.0-13.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vulkan-1.1.73.0-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vulkan-devel-1.1.73.0-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vulkan-filesystem-1.1.73.0-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xcb-proto-1.13-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xkeyboard-config-2.24-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xkeyboard-config-devel-2.24-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-drv-ati-18.0.1-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-drv-dummy-0.3.7-1.el7.1', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-drv-evdev-2.10.6-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-drv-evdev-devel-2.10.6-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-drv-fbdev-0.5.0-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-drv-intel-2.99.917-28.20180530.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-drv-intel-devel-2.99.917-28.20180530.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-drv-libinput-0.27.1-2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-drv-libinput-devel-0.27.1-2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-drv-mouse-1.9.2-2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-drv-mouse-devel-1.9.2-2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-drv-nouveau-1.0.15-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'xorg-x11-drv-openchrome-0.5.0-3.el7.1', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-drv-openchrome-devel-0.5.0-3.el7.1', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-drv-qxl-0.1.5-4.el7.1', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-drv-synaptics-1.9.0-2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-drv-synaptics-devel-1.9.0-2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-drv-v4l-0.2.0-49.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-drv-vesa-2.4.0-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-drv-vmmouse-13.1.0-1.el7.1', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-drv-vmware-13.2.1-1.el7.1', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-drv-void-1.4.1-2.el7.1', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-drv-wacom-0.36.1-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-drv-wacom-devel-0.36.1-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-font-utils-7.5-21.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'xorg-x11-proto-devel-2018.4-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-server-Xdmx-1.20.1-3.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-server-Xephyr-1.20.1-3.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-server-Xnest-1.20.1-3.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-server-Xorg-1.20.1-3.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-server-Xspice-0.1.5-4.el7.1', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-server-Xvfb-1.20.1-3.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-server-Xwayland-1.20.1-3.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-server-common-1.20.1-3.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-server-devel-1.20.1-3.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-server-source-1.20.1-3.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-utils-7.5-23.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-xkb-extras-7.7-14.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-xkb-utils-7.7-14.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-xkb-utils-devel-7.7-14.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = 'EL' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && _release) {
    if (exists_check) {
        if (rpm_exists(release:_release, rpm:exists_check) && rpm_check(release:_release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    } else {
        if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    }
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'drm-utils / egl-utils / freeglut / etc');
}
