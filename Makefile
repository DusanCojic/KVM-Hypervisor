mini_hypervisor: mini_hypervisor.c
	gcc -lpthread mini_hypervisor.c -o mini_hypervisor

GUEST_SRCS := $(wildcard guest*.c)
GUEST_IMGS := $(GUEST_SRCS:.c=.img)

guests: $(GUEST_IMGS)

%.img: %.o
	ld -T guest.ld $^ -o $@

%.o: %.c
	$(CC) -m64 -ffreestanding -fno-pic -c -o $@ $<

clean:
	rm -f mini_hypervisor
	rm -f *.o $(GUEST_IMGS)
