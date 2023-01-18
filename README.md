# install dwm
-------

  sudo pacman -S base-devel git nano
  git clone https://git.suckless.org/dwm
  git clone https://git.suckless.org/st
  sudo pacman -S xorg-server xorg-xinit libxft libxinerama libx11 webkit2gtk
  cd
  nano .xinitrc
  {
    exec dwm
  }
  cd st/ && sudo make clean install && cd ../dwm/
  sudo nano config.h
  {
    //CHANGE /bin/sh/ TO: /usr/local/bin/st             (use 'which st' to locate st location
    //CHANGE Mod1Mask(alt) TO Mod4Mask(win)
  }
  sudo make clean install
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
  cd opendoas-sudo/
  su
  pacman -Rsn sudo
  exit
  makepkg -si
  doas nano /etc/doas.conf
  {
    permit persist :wheel
  }
  usermod -G wheel worm
  su
  doas -C /etc/doas.conf

-------
