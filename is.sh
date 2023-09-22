if [ ! -z "$1" ];
then
	aarch64-linux-gnu-gcc-9 -march=armv8.3-a -lpthread -static -o init$1 init_program/test$1.c
	sudo mount -o loop myinitrd.img rootfs/	
	sudo rm rootfs/init$1
	sudo cp init$1 rootfs/
	sudo umount rootfs
else
	echo "No number"
fi
