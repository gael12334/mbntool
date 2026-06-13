//
// Copyright (c) 2026, Gaël Fortier. All rights reserved.
//

#include <elf.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define ERR_FOPEN 1
#define ERR_FREAD 2
#define ERR_MAGIC 3
#define ERR_CMD 4

typedef struct qcom_mbn_hdr {
  uint32_t magic[5];
  uint32_t entoff;
  uint32_t entptr;
  uint32_t certend;
  uint32_t certoff;
  uint32_t keyptr;
  uint32_t keysize;
  uint32_t dataptr;
  uint32_t datasize;
  uint32_t mystery[3];
  uint32_t reserved[4];
} qcom_mbn_hdr_t;

void show_help(void) {
  const char message[] = "Scan MBN file\n"
                         "Usage:\n"
                         "\tmbntool scan <mbn file>\n\n"
                         "Convert MBN to ELF\n"
                         "Usage:\n"
                         "\tmbntool elf32 <mbn file> <output elf>\n"
                         "\tmbntool elf64 <mbn file> <output elf>\n";
  puts(message);
}

FILE *open_mbn(const char *path) {
  FILE *mbn = fopen(path, "rb");
  if (mbn == NULL) {
    puts("Failed opening specified file.");
    return NULL;
  }
  return mbn;
}

FILE *new_elf(const char *path) {
  FILE *elf = fopen(path, "wb");
  if (elf == NULL) {
    puts("Failed to create elf file.");
    return NULL;
  }

  return elf;
}

int load_mbn_header(qcom_mbn_hdr_t *hdr, FILE *file) {
  memset(hdr, 0, sizeof(*hdr));
  long read = fread(hdr, sizeof(*hdr), 1, file);
  if (read != 1) {
    puts("Failed to read header info!");
    fclose(file);
    return ERR_FREAD;
  }

  if (hdr->magic[0] != 0x844BDCD1) {
    puts("Invalid MBN file: magic number is invalid.");
    fclose(file);
    return ERR_MAGIC;
  }

  return 0;
}

void show_mbn_header(qcom_mbn_hdr_t *mbnhdr) {
  qcom_mbn_hdr_t hdr = *mbnhdr;
  printf("entry off: 0x%X (%u)\n", hdr.entoff, hdr.entoff);
  printf("entry adr: 0x%X (%u)\n", hdr.entptr, hdr.entptr);
  printf("entry end: 0x%X (%u)\n", hdr.certoff + hdr.entoff - 1,
         hdr.certoff + 49);
  printf("cert off:  0x%X (%u)\n", hdr.certoff + hdr.entoff,
         hdr.certoff + hdr.entoff);
  printf("key size:  0x%X (%u)\n", hdr.keysize, hdr.keysize);
  printf("cert size: 0x%X (%u)\n", hdr.datasize + hdr.keysize,
         hdr.datasize + hdr.keysize);
}

int scan_mbn(const char *path) {
  FILE *mbn = open_mbn(path);
  if (mbn == NULL) {
    return ERR_FOPEN;
  }

  qcom_mbn_hdr_t hdr;
  int result = load_mbn_header(&hdr, mbn);
  if (result != 0) {
    return result;
  }

  show_mbn_header(&hdr);
  fclose(mbn);
  return 0;
}

int to_elf32(const char *mbn_path, const char *elf_path) {
  FILE *mbn = open_mbn(mbn_path);
  if (mbn == NULL) {
    return ERR_FOPEN;
  }

  qcom_mbn_hdr_t hdr;
  int result = load_mbn_header(&hdr, mbn);
  if (result != 0) {
    return result;
  }

  FILE *elf = new_elf(elf_path);
  if (elf == NULL) {
    fclose(mbn);
    return ERR_FOPEN;
  }

  Elf32_Ehdr elfhdr = {
      .e_ident = {0x7F, 'E', 'L', 'F', ELFCLASS32, ELFDATA2LSB, EV_CURRENT,
                  /**/ 0, 0, 0, 0, 0, 0, 0, 0, 0},
      .e_type = ET_EXEC,
      .e_machine = EM_NONE,
      .e_version = EV_CURRENT,
      .e_entry = hdr.entptr,
      .e_phoff = sizeof(elfhdr),
      .e_shoff = 0,
      .e_flags = 0,
      .e_ehsize = sizeof(elfhdr),
      .e_phentsize = sizeof(Elf32_Phdr),
      .e_phnum = 3,
      .e_shentsize = 0,
      .e_shnum = 0,
      .e_shstrndx = 0,
  };

  Elf32_Phdr nullphdr = {0};

  Elf32_Phdr textphdr = {
      .p_type = PT_LOAD,
      .p_flags = PF_R | PF_X,
      .p_offset = 0,
      .p_vaddr = hdr.entptr,
      .p_paddr = hdr.entptr,
      .p_filesz = hdr.certoff - hdr.entoff,
      .p_memsz = hdr.certoff - hdr.entoff,
      .p_align = 4,
  };

  Elf32_Phdr certphdr = {
      .p_type = PT_LOAD,
      .p_flags = PF_R,
      .p_offset = 0,
      .p_vaddr = hdr.keyptr,
      .p_paddr = hdr.keyptr,
      .p_filesz = hdr.keysize + hdr.datasize,
      .p_memsz = hdr.keysize + hdr.datasize,
      .p_align = 4,
  };

  long elfhdr_size = sizeof(elfhdr) + 3 * sizeof(nullphdr);
  textphdr.p_offset = elfhdr_size;
  certphdr.p_offset = hdr.certoff + elfhdr_size;

  fwrite(&elfhdr, sizeof(elfhdr), 1, elf);
  fwrite(&nullphdr, sizeof(nullphdr), 1, elf);
  fwrite(&textphdr, sizeof(textphdr), 1, elf);
  fwrite(&certphdr, sizeof(certphdr), 1, elf);

  char bytes[512];
  long read;
  long wrote;
  while ((read = fread(bytes, 1, sizeof(bytes), mbn))) {
    wrote = fwrite(bytes, 1, read, elf);
    if (wrote != read) {
      puts("Warning! length written differs from length read.");
    }
  }

  fclose(mbn);
  fclose(elf);
  show_mbn_header(&hdr);
  return 0;
}

int to_elf64(const char *mbn_path, const char *elf_path) {
  FILE *mbn = open_mbn(mbn_path);
  if (mbn == NULL) {
    return ERR_FOPEN;
  }

  qcom_mbn_hdr_t hdr;
  int result = load_mbn_header(&hdr, mbn);
  if (result != 0) {
    return result;
  }

  FILE *elf = new_elf(elf_path);
  if (elf == NULL) {
    fclose(mbn);
    return ERR_FOPEN;
  }

  Elf64_Ehdr elfhdr = {
      .e_ident = {0x7F, 'E', 'L', 'F', ELFCLASS64, ELFDATA2LSB, EV_CURRENT,
                  /**/ 0, 0, 0, 0, 0, 0, 0, 0, 0},
      .e_type = ET_EXEC,
      .e_machine = EM_NONE,
      .e_version = EV_CURRENT,
      .e_entry = hdr.entptr,
      .e_phoff = sizeof(elfhdr),
      .e_shoff = 0,
      .e_flags = 0,
      .e_ehsize = sizeof(elfhdr),
      .e_phentsize = sizeof(Elf64_Phdr),
      .e_phnum = 3,
      .e_shentsize = 0,
      .e_shnum = 0,
      .e_shstrndx = 0,
  };

  Elf64_Phdr nullphdr = {0};

  Elf64_Phdr textphdr = {
      .p_type = PT_LOAD,
      .p_flags = PF_R | PF_X,
      .p_offset = 0,
      .p_vaddr = hdr.entptr,
      .p_paddr = hdr.entptr,
      .p_filesz = hdr.certoff - hdr.entoff,
      .p_memsz = hdr.certoff - hdr.entoff,
      .p_align = 1,
  };

  Elf64_Phdr certphdr = {
      .p_type = PT_LOAD,
      .p_flags = PF_R,
      .p_offset = 0,
      .p_vaddr = hdr.keyptr,
      .p_paddr = hdr.keyptr,
      .p_filesz = hdr.keysize + hdr.datasize,
      .p_memsz = hdr.keysize + hdr.datasize,
      .p_align = 1,
  };

  long elfhdr_size = sizeof(elfhdr) + 3 * sizeof(nullphdr);
  textphdr.p_offset = elfhdr_size;
  certphdr.p_offset = hdr.certoff + elfhdr_size;

  fwrite(&elfhdr, sizeof(elfhdr), 1, elf);
  fwrite(&nullphdr, sizeof(nullphdr), 1, elf);
  fwrite(&textphdr, sizeof(textphdr), 1, elf);
  fwrite(&certphdr, sizeof(certphdr), 1, elf);

  char bytes[512];
  long read;
  long wrote;
  while ((read = fread(bytes, 1, sizeof(bytes), mbn))) {
    wrote = fwrite(bytes, 1, read, elf);
    if (wrote != read) {
      puts("Warning! length written differs from length read.");
    }
  }

  fclose(mbn);
  fclose(elf);
  show_mbn_header(&hdr);
  return 0;
}

int main(int argc, char **argv) {
  if (argc < 3 || argc > 4) {
    show_help();
    return ERR_CMD;
  }

  if (strcmp(argv[1], "scan") == 0) {
    if (argc != 3) {
      show_help();
      return ERR_CMD;
    }
    return scan_mbn(argv[2]);
  }

  if (strcmp(argv[1], "elf32") == 0) {
    if (argc != 4) {
      show_help();
      return ERR_CMD;
    }
    return to_elf32(argv[2], argv[3]);
  }

  if (strcmp(argv[1], "elf64") == 0) {
    if (argc != 4) {
      show_help();
      return ERR_CMD;
    }
    return to_elf64(argv[2], argv[3]);
  }

  show_help();
  return ERR_CMD;
}
