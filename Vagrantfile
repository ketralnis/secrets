Vagrant.configure(2) do |config|

  config.vm.box = "trusty-cloud-image"
  config.vm.box_url = "https://cloud-images.ubuntu.com/vagrant/trusty/current/trusty-server-cloudimg-amd64-vagrant-disk1.box"

  config.vm.provider "virtualbox" do |v|
    # these speed up compilation quite a lot. rustc uses a lot of RAM and cargo
    # does a good job at using multiple cores
    v.memory = 2048
    v.cpus = 4
  end

  guest_ip = "dhcp"

  if guest_ip == "dhcp"
    config.vm.network "private_network", type: guest_ip
  else
    config.vm.network "private_network", ip: guest_ip
  end

    config.vm.network "forwarded_port", host: 4430, guest: 4430
  config.vm.hostname = "secrets.vm"

  # project synced folder
  config.vm.synced_folder  ".", "/home/vagrant/secrets",
    type: "rsync",
    rsync__auto: false,
    rsync__exclude: ["target", "tmp"]

  config.vm.provision "shell",
    path: "./bootstrap.sh"
end
