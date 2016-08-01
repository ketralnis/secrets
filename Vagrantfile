Vagrant.configure(2) do |config|

  config.vm.box = "trusty-cloud-image"
  config.vm.box_url = "https://cloud-images.ubuntu.com/vagrant/trusty/current/trusty-server-cloudimg-amd64-vagrant-disk1.box"

  config.vm.provider "virtualbox" do |v|
    # these speed up compilation quite a lot
    v.memory = 1024
    v.cpus = 2
  end

  guest_ip = "dhcp"

  if guest_ip == "dhcp"
    config.vm.network "private_network", type: guest_ip
  else
    config.vm.network "private_network", ip: guest_ip
  end

  config.vm.hostname = "secrets.vm"

  # project synced folder
  config.vm.synced_folder  ".", "/home/vagrant/secrets",
    type: "rsync",
    rsync__auto: false,
    rsync__exclude: ["target", "tmp"]

  config.vm.provision "shell",
    path: "./bootstrap.sh"
end
