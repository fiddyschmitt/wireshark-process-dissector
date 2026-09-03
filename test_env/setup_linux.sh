#!/bin/bash
# Guest provisioning for the dissector desktop test VM. Run once by cloud-init (runcmd) on
# first boot. Installs an XFCE desktop + LightDM autologin + Wireshark, wires up non-root
# capture, and drops the process dissector (plugin + column preferences) into place so the
# desktop is ready to use. Signals completion with /run/dissector-setup-complete.
set -x
exec > /var/log/dissector-setup.log 2>&1
echo "=== dissector VM provisioning started $(date) ==="

export DEBIAN_FRONTEND=noninteractive

# Let non-root users capture (Wireshark's setuid dumpcap path); answered before the package installs.
echo "wireshark-common wireshark-common/install-setuid boolean true" | debconf-set-selections

apt-get update -y

# Desktop, display manager, Wireshark, and a browser + tools to generate/inspect traffic.
# NOTE: the X server (xserver-xorg*) is listed EXPLICITLY. xfce4 only *recommends* it, so with
# --no-install-recommends it would be skipped and LightDM could not start a display. The VMSVGA
# graphics controller needs the "vmware" Xorg driver (modesetting via vmwgfx also works).
apt-get install -y --no-install-recommends \
  xserver-xorg xserver-xorg-core xinit \
  xserver-xorg-video-vmware xserver-xorg-input-libinput \
  xfce4 xfce4-terminal xfce4-goodies \
  lightdm lightdm-gtk-greeter \
  wireshark tshark \
  firefox-esr curl wget git nano xterm dbus-x11 \
  || apt-get install -y xorg xfce4 lightdm wireshark tshark curl firefox-esr xterm dbus-x11

# Non-root capture: add the desktop user to the wireshark group and make sure dumpcap has caps.
usermod -aG wireshark user || true
dpkg-reconfigure -f noninteractive wireshark-common || true
setcap 'cap_net_raw,cap_net_admin+eip' /usr/bin/dumpcap || true

# VirtualBox Guest Additions (dynamic resolution, clipboard, mouse integration). Debian 13's
# repos carry no virtualbox-guest-* packages, so install from the host's VBoxGuestAdditions.iso,
# which the orchestrator attaches as a second DVD. Needs kernel headers + a toolchain for the
# vboxguest/vboxvideo modules. Best-effort: the desktop works without it, just at a fixed size.
# (contrib is enabled too — deb822 sources on Debian 13 — for anything else that needs it.)
sed -i 's/^Components: main$/Components: main contrib/' /etc/apt/sources.list.d/debian.sources 2>/dev/null || true
sed -i 's/^\(deb .*trixie main\)$/\1 contrib/' /etc/apt/sources.list 2>/dev/null || true
apt-get update -y || true
install_guest_additions() {
    apt-get install -y build-essential dkms "linux-headers-$(uname -r)" || apt-get install -y build-essential dkms linux-headers-amd64 || return 1
    GA_DEV=""
    for d in /dev/sr1 /dev/sr0 /dev/sr2; do
        [ -b "$d" ] || continue
        if blkid -o value -s LABEL "$d" 2>/dev/null | grep -qi "VBox_GAs\|VBOXADDITIONS"; then GA_DEV="$d"; break; fi
    done
    [ -n "$GA_DEV" ] || { echo "no Guest Additions ISO attached"; return 1; }
    mkdir -p /mnt/vboxga && mount -o ro "$GA_DEV" /mnt/vboxga || return 1
    # exit code 2 = "reboot needed" for the modules, which is fine on first boot
    sh /mnt/vboxga/VBoxLinuxAdditions.run --nox11; rc=$?
    umount /mnt/vboxga 2>/dev/null
    [ "$rc" -eq 0 ] || [ "$rc" -eq 2 ]
}
install_guest_additions || echo "guest additions not installed (non-fatal)"

# LightDM autologin so the XFCE desktop comes up in the VirtualBox window with no password prompt.
mkdir -p /etc/lightdm/lightdm.conf.d
cat > /etc/lightdm/lightdm.conf.d/50-autologin.conf <<'EOF'
[Seat:*]
autologin-user=user
autologin-user-timeout=0
user-session=xfce
EOF
groupadd -f autologin
usermod -aG autologin user || true

# Drop the dissector bundle (staged by cloud-init at /opt/dissector-bundle.tgz) into the user's home.
mkdir -p /home/user/dissector
tar xzf /opt/dissector-bundle.tgz -C /home/user/dissector

# Wireshark personal plugin (auto-loaded) + column preferences.
mkdir -p /home/user/.local/lib/wireshark/plugins /home/user/.config/wireshark
cp /home/user/dissector/process_dissector.lua /home/user/.local/lib/wireshark/plugins/process_dissector.lua
[ -f /home/user/dissector/preferences ] && cp /home/user/dissector/preferences /home/user/.config/wireshark/preferences

# Desktop conveniences: a Wireshark launcher and a one-click traffic generator for manual checks.
mkdir -p /home/user/Desktop
cat > /home/user/Desktop/Wireshark.desktop <<'EOF'
[Desktop Entry]
Type=Application
Name=Wireshark
Comment=Capture with the Process Info dissector
Exec=wireshark
Icon=wireshark
Terminal=false
EOF
cat > /home/user/Desktop/Generate-Traffic.desktop <<'EOF'
[Desktop Entry]
Type=Application
Name=Generate Traffic
Comment=Make some TCP/UDP connections so the process columns populate
Exec=xfce4-terminal --hold -e "bash -lc 'for i in 1 2 3 4 5; do curl -s -o /dev/null https://example.com; curl -s -o /dev/null https://www.debian.org; getent hosts wikipedia.org >/dev/null; sleep 1; done; echo done'"
Icon=utilities-terminal
Terminal=false
EOF
chmod +x /home/user/Desktop/*.desktop || true

chown -R user:user /home/user/dissector /home/user/.local /home/user/.config /home/user/Desktop

# Boot to the graphical target and start the desktop now (after group membership is set).
systemctl set-default graphical.target
systemctl enable lightdm
systemctl start lightdm || true

echo "=== dissector VM provisioning complete $(date) ==="
# Two markers: /run is tmpfs (cleared on reboot) and is what the first-boot wait polls;
# /var/lib persists so 'status' still reports the VM as provisioned after any reboot.
touch /run/dissector-setup-complete
mkdir -p /var/lib/dissector && touch /var/lib/dissector/setup-complete
