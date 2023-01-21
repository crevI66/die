# install dwm
-------

    sudo pacman -S base-devel xorg-xinit xorg git nano
    git clone https://git.suckless.org/dwm
    git clone https://git.suckless.org/st
    git clone https://git.suckless.org/dmenu
    //alt: git clone https://github.com/crevI66/fucki3
    cd dwm ## Do this step also with st and dmenu
    sudo make clean install
    cd
    nano .xinitrc
    {
      exec dwm
    }
    cd
    nano .bash_profile
    {
      startx
    }
    alt + shift + q(exit dwm)
  
-------

# install doas
-------

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
    
-------
