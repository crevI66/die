# package
    xorg xorg-xinit discord nnn lxappearance qt5ct arc-gtk-theme arc-icon-theme base-devel brightnessctl pavucontrol firefox flameshot keepassxc git vim
# .bashrc
    alias nnn="nnn -d -e -H -r"
    alias ls -F --color=auto --group-directories-first -a
    alias mkdir="mkdir -pv"
    alias rm="rm -iv" 
    alias cp="cp -iv" 
    alias mv="mv -iv"
    alias stfu='sudo shutdown -h now'
    alias mostused="  history | awk '{CMD[$2]++;count++;}END { for (a in CMD)print CMD[a] " " CMD[a]/count*100 "% " a;}' | grep -v "./" | column -c3 -s " " -t | sort -nr | nl |  head -n20"
    echo pacman -Q | wc -l
# .xinitrc
    exec dwm
    mpd &

# install dwm
    git clone https://git.suckless.org/dwm
    git clone https://git.suckless.org/st
    git clone https://git.suckless.org/dmenu
    //alt: git clone https://github.com/crevI66/die
    cd dwm ## Do this step also with st and dmenu
    sudo make clean install
    alt + shift + q(exit dwm)

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
    

