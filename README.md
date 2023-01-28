-------
|Just watch what you're doing when using pacman and actually read PKGBUILDs if you're installing stuff from the AUR and  you should be ok. Do not update literally every minute like some morons tell you to. Update weekly and if you're going to install a new package and haven't done so in a while.

Do NOT check for updates by running "pacman -Syu" and canceling. This can fuck you up. Install pacman-contrib and run "checkupdates" instead.

If you're using Yay, I think it allows you to inspect PKGBUILDs by default. "yay -Pw" also is pretty handy to run before updates because if something requires manual intervention, it'll be posted on the front page of the arch website. If you don't want to use yay, subscribe to the rss feed or the mailing list.
   |
Enable paccache.timer to clear the package cache weekly
If using an SSD, enable fstrim.timer to discard unused blocks periodically
Setup a firewall such as ufw or firewalld
Install and configure reflector to frequently update the mirrorlist automatically
Enable Parallel Downloads in /etc/pacman.conf
Install intel-ucode or amd-ucode microcode depending on your CPU
For laptops, setup CPU frequency scaling and optimise battery life with tlp, autocpu-freq, powertop or power-profiles-daemon etc
Install a backup kernel like LTS or Zen kernel
For NVIDIA users, create a pacman hook to ensure initramfs gets updated on every nvidia or kernel upgrade
Install noto-fonts for basic font coverage
"pacman" effect to the download progress bars:
Edit /etc/pacman.conf and under [options] add ILoveCandy and Color. (both case sensitive)

-------



# package
    //vulkan-intel lib32-vulkan-intel
    //wine
    /*pacman -S --needed wine-staging giflib lib32-giflib libpng lib32-libpng libldap lib32-libldap gnutls lib32-gnutls \
mpg123 lib32-mpg123 openal lib32-openal v4l-utils lib32-v4l-utils libpulse lib32-libpulse libgpg-error \
lib32-libgpg-error alsa-plugins lib32-alsa-plugins alsa-lib lib32-alsa-lib libjpeg-turbo lib32-libjpeg-turbo \
sqlite lib32-sqlite libxcomposite lib32-libxcomposite libxinerama lib32-libgcrypt libgcrypt lib32-libxinerama \
ncurses lib32-ncurses ocl-icd lib32-ocl-icd libxslt lib32-libxslt libva lib32-libva gtk3 \
lib32-gtk3 gst-plugins-base-libs lib32-gst-plugins-base-libs vulkan-icd-loader lib32-vulkan-icd-loader*/

    bluez bluez-utils virtualbox linux-headers nvidia-dkms nvidia-utils lib32-nvidia-utils nvidia-settings vulkan-icd-loader lib32-vulkan-icd-loader pacman-contrib reflector xorg xorg-xinit discord nnn lxappearance qt5ct arc-gtk-theme arc-icon-theme base-devel brightnessctl pavucontrol firefox flameshot keepassxc git vim
    
# bluetoothctl
    power on 
    agent on 
    default-agent 
    scan on 
    trust 
    pair 
    connect 
    
# .bashrc
    alias nnn="nnn -d -e -H -r"
    alias ls="ls -F --color=auto --group-directories-first -a"
    alias mkdir="mkdir -pv"
    alias rm="rm -iv" 
    alias cp="cp -iv" 
    alias mv="mv -iv"
    alias stfu="shutdown -h now"
    alias updatemirror="reflector --verbose -c Vietnam --sort rate -l 30 --save /etc/pacman.d/mirrorlist"
    pacman -Q | wc -l
    
# .xinitrc
    exec dwm

# install dwm
    git clone https://git.suckless.org/dwm
    git clone https://git.suckless.org/st
    git clone https://git.suckless.org/dmenu
    //alt: git clone https://github.com/crevI66/die
    cd dwm ## Do this step also with st and dmenu
    sudo make clean install

# install doas
    git clone https://aur.archlinux.org/opendoas-sudo.git
    sudo make clean install
    nano /etc/doas.conf
    {
        permit persist :wheel
        
    }
    doas -C /etc/doas.conf
    chown -c root:root /etc/doas.conf
    chmod -c 0400 /etc/doas.conf
    doas -Rsn sudo
    

