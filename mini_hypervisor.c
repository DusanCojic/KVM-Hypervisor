#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <string.h>
#include <stdint.h>
#include <linux/kvm.h>
#include <sys/stat.h>
#include <getopt.h>
#include <pthread.h>

#define MAX_GUESTS 10
#define MAX_FILES 10

// PDE bits
#define PDE64_PRESENT (1u << 0) // present in memory
#define PDE64_RW (1u << 1) // read/write
#define PDE64_USER (1u << 2) // can be accessed in user mode
#define PDE64_PS (1u << 7) // indicates where PDE points (next-level page table or large page)

// CR4 (enables processor extensions) and CR0 (controls basic processor operating mode)
#define CR0_PE (1u << 0) // protected mode enabled
#define CR0_PG (1u << 31) // pagingz
#define CR4_PAE (1u << 5) // physical address extension

#define EFER_LME (1u << 8) // long mode enable
#define EFER_LMA (1u << 10) // long mode activate

#define GUEST_START_ADDR 0x0

// struct below represents a virtual machine
struct vm {
    int kvm_fd;
    int vm_fd;
    int vcpu_fd;
    uint8_t* mem;
    size_t mem_size;
    struct kvm_run* run;
    int run_mmap_size;
};

// struct below represents an open file
struct file {
    char path[256]; // path to file
    uint64_t fd; // file descriptor for the file
    int mode; // 0 - read, 1 - read/write
    int shared; // indicates whether file is local or shared between vms

    int op; // operation on file
    void* buff; // buffer to read from / write into
    uint64_t temp; // for storing buffer size, receiving return values, etc...
};

// file operations
enum { OPEN, CLOSE, READ, WRITE };

int vm_init(struct vm* v, size_t mem_size) {
    struct kvm_userspace_memory_region region;

    // initialize vm struct to initial values
    memset(v, 0, sizeof(struct vm));
    v->kvm_fd = v->vm_fd = v->vcpu_fd = -1;
    v->mem = MAP_FAILED;
    v->run = MAP_FAILED;
    v->run_mmap_size = 0;
    v->mem_size = mem_size;

    // open /dev/kvm device
    v->kvm_fd = open("/dev/kvm", O_RDWR);
    if (v->kvm_fd < 0) { perror("open /dev/kvm"); return -1; }

    // create new vm
    v->vm_fd = ioctl(v->kvm_fd, KVM_CREATE_VM, 0);
    if (v->vm_fd < 0) { perror("KVM_CREATE_VM"); return -1; }

    // RAM for the vm
    v->mem = mmap(NULL, mem_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (v->mem == MAP_FAILED) { perror("mmap mem"); return -1; }

    // setup memory region to be used by the guest
    region.slot = 0; // unique ID for the region
    region.flags = 0; // no special behaviour
    region.guest_phys_addr = 0; // start of the guests physical memory
    region.memory_size = v->mem_size;
    region.userspace_addr = (uintptr_t)v->mem; // memory in VMMs address space that backs guests RAM
    if (ioctl(v->vm_fd, KVM_SET_USER_MEMORY_REGION, &region) < 0) { perror("KVM_SET_USER_MEMORY_REGION"); return -1; }

    // create virtual cpu
    v->vcpu_fd = ioctl(v->vm_fd, KVM_CREATE_VCPU, 0);
    if (v->vcpu_fd < 0) { perror("KVM_CREATE_VCPU"); return -1; }

    // get mem size for kvm_run structure
    v->run_mmap_size = ioctl(v->kvm_fd, KVM_GET_VCPU_MMAP_SIZE, 0);
    if (v->run_mmap_size <= 0) { perror("KVM_GET_VCPU_MMAP_SIZE"); return -1; }

    // initialize kvm_run
    v->run = mmap(NULL, v->run_mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, v->vcpu_fd, 0);
    if (v->run == MAP_FAILED) { perror("mmap kvm_run"); return -1; }

    return 0;
}

void vm_destroy(struct vm* v) {
    // unmap kvm_run structure
    if (v->run && v->run != MAP_FAILED) { munmap(v->run, (size_t)v->run_mmap_size); v->run = MAP_FAILED; }

    // unmap memory used for guests RAM
    if (v->mem && v->mem != MAP_FAILED) { munmap(v->mem, v->mem_size); v->mem = MAP_FAILED; }

    // close vcpu file
    if (v->vcpu_fd >= 0) { close(v->vcpu_fd); v->vcpu_fd = -1; }

    // close vm file
    if (v->vm_fd >= 0) { close(v->vm_fd); v->vm_fd = -1; }

    // close kvm file
    if (v->kvm_fd >= 0) { close(v->kvm_fd); v->kvm_fd = -1; }
}

static void setup_segments_64(struct kvm_sregs* sregs) {
    struct kvm_segment code = {
        .base = 0, // base address
        .limit = 0xffffffff, // limit
        .present = 1, // present in memory
        .type = 11, // code: read/write/execute
        .dpl = 0, // descriptor  privilege level (0 - kernel)
        .db = 0, // default operation size (0 = 16/64-bit)
        .s = 1, // descriptor type (1 - code/data)
        .l = 1, // 64-bit segment flag
        .g = 1 // granularity (0 - byte, 1 - 4KB)
    };

    struct kvm_segment data = code;
    data.type = 3; // data: read/write/execute
    data.l = 0; // 16/32-bit segment flag

    // set code segment
    sregs->cs = code;
    // in flat model, all other segments are pointing to the same region of memory
    // (all segments cover full address space)
    sregs->ds = sregs->es = sregs->fs = sregs->gs = sregs->ss = data;
}

static void setup_long_mode(struct vm* v, struct kvm_sregs* sregs, int page_size, int mem_size) {
    // 4 levels of paging, every table hase 512 entries and every entry is 8B -> one page table is 4KB
    // all tables must be alligned at 4KB, because some bits have different purpose 

    uint64_t page = 0;
    
    // setup 4th level
    uint64_t pml4_addr = 0x1000;
    uint64_t* pml4 = (void*)(v->mem + pml4_addr);

    //setup 3rd level
    uint64_t pdpt_addr = 0x2000;
    uint64_t* pdpt = (void*)(v->mem + pdpt_addr);

    // setup 2nd level
    uint64_t pd_addr = 0x3000;
    uint64_t* pd = (void*)(v->mem + pd_addr);

    // initialzie page tables
    pml4[0]  = (pdpt_addr & ~0xFFFULL) | PDE64_PRESENT | PDE64_RW | PDE64_USER;
    pdpt[0]  = (pd_addr  & ~0xFFFULL) | PDE64_PRESENT | PDE64_RW | PDE64_USER;

    // setup and initialize the rest
    int msize = mem_size / (1024u * 1024u);
    for (int i = 0; i < msize / 2; i++) {
        if (page_size == 4) {
            uint64_t pt_addr = 0x4000 + 0x1000 * i;
            uint64_t* pt = (void*)(v->mem + pt_addr);

            pd[i] = PDE64_PRESENT | PDE64_RW | PDE64_USER | pt_addr;

            for (int j = 0; j < 512; j++) {
                pt[j] = page | PDE64_PRESENT | PDE64_RW | PDE64_USER;
                page += 0x1000;
            }
        }
        else
            pd[i] = PDE64_PRESENT | PDE64_RW | PDE64_USER | PDE64_PS | (2u * 1024u * 1024u * i);
    }
    

    // initialize registers
    sregs->cr3 = pml4_addr; // register that points to PML4 (top-level page table)
    sregs->cr4 |= CR4_PAE; // enable Physical Address Extension (required for 64-bit mode) - more than 4GB of RAM (uses 36-bit)
    sregs->cr0 |= CR0_PE | CR0_PG; // PE - protected mode, PG - enable paging
    sregs->efer |= EFER_LME | EFER_LMA; // LME - enable long mode, LMA - long mode enabled

    // segment initialization
    setup_segments_64(sregs);
}

int load_guest_image(struct vm* v, const char* image_path, uint64_t load_addr) {
    // open guest image
    FILE* f = fopen(image_path, "rb");
    if (!f) { perror("Failed to open guest image"); return -1; }

    // get image size
    struct stat st;
    if (fstat(fileno(f), &st) < 0) { perror("Failed to stat guest image"); fclose(f); return -1; }
    uint64_t fsz = (uint64_t)st.st_size;

    // check if vm memory is large enough for the image
    if (fsz > v->mem_size - load_addr) {
        printf("Guest image is too large for the VM memory\n");
        fclose(f);
        return -1;
    }

    // read the guest image
    if (fread((uint8_t*)v->mem + load_addr, 1, (size_t)fsz, f) != (size_t)fsz) {
        perror("Failed to read guest image");
        fclose(f);
        return -1;
    }

    fclose(f);
    return 0;
}

void create_unique_filename(char* path, int id, char* newName, int newNameSize) {
    // add vm id to the file name

    char* dot = strrchr(path, '.');
    if (dot) {
        // file has extension
        size_t basename_len = dot - path;
        snprintf(newName, newNameSize, "%.*s%d%s", (int)basename_len, path, id, dot);
    }
    else {
        // file does not have extension
        snprintf(newName, newNameSize, "%s%d", path, id);
    }
}

int check_file_in_list(char* files[MAX_FILES], int file_count, char* file) {
    for (int i = 0; i < file_count; i++) {
        if (strcmp(files[i], file) == 0)
            return 1;
    }
    return 0;
}

int copy_file(int fd, int newFd) {
    ssize_t bytes_read, bytes_written;
    char buffer[4096];
    lseek(fd, 0, SEEK_SET);

    // copy whole file
    while ((bytes_read = read(fd, buffer, sizeof(buffer))) > 0) {
        char* buff_ptr = buffer;
        ssize_t remain = bytes_read;

        while (remain > 0) {
            bytes_written = write(newFd, buff_ptr, remain);
            if (bytes_written <= 0) {
                fprintf(stderr, "Error while copying the file\n");
                close(newFd);
                close(fd);
                return -1;
            }

            remain -= bytes_written;
            buff_ptr += bytes_written;
        }
    }

    if (bytes_read < 0) {
        fprintf(stderr, "Error while reading the file\n");
        close(newFd);
        close(fd);
        return -1;
    }

    return 0;
}

// parameters required for vms
struct vm_args {
    int id;
    size_t mem_size;
    int page_size;
    char* guest_file;
    char* shared_files[MAX_FILES];
    int shared_count;
};

void* vm_thread(void* args) {
    struct vm_args* vargs = (struct vm_args*)args;

    // create all necessary structures
    struct vm* v = (struct vm*)malloc(sizeof(struct vm));
    struct kvm_sregs sregs;
    struct kvm_regs regs;
    uint8_t stop = 0;

    // initialize VM with mem size
    if (vm_init(v, vargs->mem_size)) { printf("Failed to init the VM\n"); free(v); return NULL; }

    // get special regs
    if (ioctl(v->vcpu_fd, KVM_GET_SREGS, &sregs) < 0) { perror("KVM_GET_SREGS"); vm_destroy(v); free(v); return NULL; }

    setup_long_mode(v, &sregs, vargs->page_size, vargs->mem_size);

    // set special regs
    if (ioctl(v->vcpu_fd, KVM_SET_SREGS, &sregs) < 0) { perror("KVM_SET_SREGS"); vm_destroy(v); free(v); return NULL; }

    // load gues image
    if (load_guest_image(v, vargs->guest_file, GUEST_START_ADDR) < 0) {
        printf("Failed to load guest image\n");
        vm_destroy(v);
        free(v);
        return NULL;
    }

    // initialzie standard regs
    memset(&regs, 0, sizeof(regs));
    regs.rflags = 0x2; // set reserved bit 1 (must always be 1)
    regs.rip = 0; // instruction pointer
    regs.rsp = 0x1FFFF8ULL; // set stack pointer

    // set standard regs
    if (ioctl(v->vcpu_fd, KVM_SET_REGS, &regs) < 0) { perror("KVM_SET_REGS"); free(v); return NULL; }

    uint8_t half_received = 0;
    uint64_t guest_addr = 0;
    // main part of the hypervisor
    while (stop == 0) {
        // run vm
        if (ioctl(v->vcpu_fd, KVM_RUN, 0) == -1) { printf("KVM_RUN failed\n"); vm_destroy(v); free(v); return NULL; }

        // check the exit reason
        switch (v->run->exit_reason) {
            case KVM_EXIT_IO:
                if (v->run->io.direction == KVM_EXIT_IO_OUT && v->run->io.port == 0xE9) {
                    uint8_t* p = (uint8_t*)v->run;
                    printf("%c", *(p + v->run->io.data_offset));
                }
                else if (v->run->io.direction == KVM_EXIT_IO_OUT && v->run->io.port == 0x278) {
                    uint32_t half_addr = *(uint32_t*)((uint8_t*)v->run + v->run->io.data_offset);

                    // receive guest address in two parts
                    if (half_received == 0) {
                        guest_addr = (uint64_t)half_addr;
                        half_received = 1;
                    }
                    else {
                        guest_addr |= ((uint64_t)half_addr << 32);
                        half_received = 0;

                        // get file struct from guest address space
                        struct file* f = (struct file*)((uint8_t*)v->mem + guest_addr);
                        switch (f->op) {
                            case OPEN:
                                char newPath[256];
                                create_unique_filename(f->path, vargs->id, newPath, sizeof(newPath));
                                if (access(newPath, F_OK) == 0) { // local file for the vm exists

                                    f->fd = open(newPath, f->mode == 1 ? O_RDWR : O_RDONLY, 0777);
                                    f->shared = 0;
                                }
                                else if (check_file_in_list(vargs->shared_files, vargs->shared_count, f->path) == 1) { // shared file exists
                                    f->fd = open(f->path, f->mode == 1 ? O_RDWR : O_RDONLY, 0777);
                                    f->shared = 1;
                                }
                                else if (f->mode == 1) { // mode is read/write, create new file
                                    f->fd = open(newPath, O_RDWR | O_CREAT, 0777);
                                    f->shared = 0;
                                }
                                else {
                                    f->fd = -1;
                                    f->shared = 0;
                                }

                                break;

                            case READ:
                                f->temp = read(f->fd, v->mem + (uintptr_t)f->buff, f->temp); // write content directly to the buffer
                                break;

                            case WRITE:
                                if (f->mode == 0) { fprintf(stderr, "Trying to write without the permission\n"); return NULL; }

                                if (f->shared == 1) {
                                    int newFd = open(newPath, O_RDWR | O_CREAT | O_TRUNC, 0777);
                                    if (newFd < 0) { fprintf(stderr, "Cannot create new file\n"); return NULL; }

                                    // copy on write
                                    copy_file(f->fd, newFd);

                                    // set fd to new one
                                    close(f->fd);
                                    f->fd = newFd;
                                    f->shared = 0;
                                }

                                // write data
                                lseek(f->fd, 0, SEEK_END);
                                f->temp = write(f->fd, v->mem + (uintptr_t)f->buff, f->temp);
                                lseek(f->fd, 0, SEEK_SET);
                                break;

                            case CLOSE:
                                f->temp = close(f->fd);
                                f->fd = -1;
                                break;
                        }
                    }
                }
                continue;

            case KVM_EXIT_HLT:
                printf("KVM_EXIT_HLT\n");
                stop = 1;
                break;

            case KVM_EXIT_SHUTDOWN:
                printf("Shutdown\n");
                stop = 1;
                break;

            default:
                printf("Default - exit reason: %d\n", v->run->exit_reason);
                break;
        }
    }

    vm_destroy(v);
    free(v);
    return NULL;
}

// struct for arguments passed from command line
struct requirements {
    size_t mem_size;
    int page_size;
    char* guest_paths[MAX_GUESTS];
    int guest_count;
    char* file_paths[MAX_FILES];
    int file_count;
};

struct requirements load_requirements(int argc, char* argv[]) {
    // check whether script hase required number of arguments
    if (argc < 7) {
        fprintf(stderr, "Usage: %s [-m memory] [-p page] [-g guest1.img guest2.img ...] [-f file1 file2 ...]\n", argv[0]);
        fprintf(stderr, "memory: 2, 4, 8 [MB], page: 4[KB], 2[MB]\n");
        exit(EXIT_FAILURE);
    }

    // valid options
    static struct option options[] = {
        { "memory", required_argument, 0, 'm' },
        { "page",   required_argument, 0, 'p' },
        { "guest",  required_argument, 0, 'g' },
        { "file", optional_argument, 0, 'f' },
        { 0, 0, 0, 0 }
    };

    // initialize
    struct requirements reqs;
    reqs.guest_count = 0;
    reqs.file_count = 0;

    int opt, opt_index = 0;
    while ((opt = getopt_long(argc, argv, "m:p:g:f::", options, &opt_index)) != -1) {
        switch (opt) {
            case 'm':
                reqs.mem_size = (size_t)(atoi(optarg) * 1024u * 1024u);
                break;

            case 'p':
                reqs.page_size = atoi(optarg);
                break;

            case 'g':
                reqs.guest_paths[reqs.guest_count++] = optarg;

                while (optind < argc && argv[optind][0] != '-')
                    reqs.guest_paths[reqs.guest_count++] = argv[optind++];

                break;

            case 'f':
                if (optarg != NULL)
                    reqs.file_paths[reqs.file_count++] = optarg;

                while (optind < argc && argv[optind][0] != '-')
                    reqs.file_paths[reqs.file_count++] = argv[optind++];

                break;

            default:
                fprintf(stderr, "Usage: %s [-m memory] [-p page] [-g guest1.img guest2.img ...] [-f file1 file2 ...]\n", argv[0]);
                fprintf(stderr, "memory: 2, 4, 8 [MB], page: 4[KB], 2[MB]\n");
                exit(EXIT_FAILURE);
        }
    }

    return reqs;
}

int main(int argc, char* argv[])
{
    // read requirements
    struct requirements reqs = load_requirements(argc, argv);

    // create required number of threads and argument structs
    pthread_t threads[reqs.guest_count];
    struct vm_args vargs[reqs.guest_count];

    // initialize arguments and run threads
    for (int i = 0; i < reqs.guest_count; i++) {
        vargs[i].id = i;
        vargs[i].guest_file = reqs.guest_paths[i];
        vargs[i].mem_size = reqs.mem_size;
        vargs[i].page_size = reqs.page_size;
        vargs[i].shared_count = reqs.file_count;
        for (int j = 0; j < reqs.file_count; j++)
            vargs[i].shared_files[j] = reqs.file_paths[j];

        pthread_create(&threads[i], NULL, vm_thread, &vargs[i]);
    }

    // wait for all of the thread to finish
    for (int i = 0; i < reqs.guest_count; i++)
        pthread_join(threads[i], NULL);

    return 0;
}
