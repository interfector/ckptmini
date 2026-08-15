#include "ckptmini.h"
#include <elf.h>

/*
 * Resolve runtime addresses in a traced process to "symbol+offset".
 *
 * The target's /proc/<pid>/maps are parsed for executable file-backed
 * mappings, then each backing ELF is read to build a (name, value, size)
 * table from .symtab/.dynsym.  For ET_DYN modules the runtime address of a
 * symbol is load_base + st_value, where load_base is derived from the map
 * start minus the p_vaddr of the PT_LOAD segment that matches the map's
 * file offset.  For ET_EXEC st_value is absolute, so load_base is 0.
 */

typedef struct {
    char *name;
    uint64_t value;
    uint64_t size;
} elfsym_t;

typedef struct {
    char *path;
    uint64_t start, end;
    uint64_t load_base;
    elfsym_t *syms;
    size_t nsyms;
} elfsym_mod_t;

static elfsym_mod_t *g_mods = NULL;
static size_t g_nmods = 0;
static size_t g_cap = 0;

static int sym_cmp(const void *a, const void *b) {
    uint64_t va = ((const elfsym_t*)a)->value, vb = ((const elfsym_t*)b)->value;
    return va < vb ? -1 : va > vb ? 1 : 0;
}

static void add_symbols(elfsym_mod_t *m, const Elf64_Sym *syms, size_t nsyms,
                        const char *strtab, size_t strsz) {
    for (size_t i = 0; i < nsyms; i++) {
        const Elf64_Sym *s = &syms[i];
        unsigned int type = ELF64_ST_TYPE(s->st_info);
        if (s->st_name == 0 || s->st_name >= strsz) continue;
        if (s->st_value == 0) continue;
        if (!(type == STT_FUNC || type == STT_GNU_IFUNC || type == STT_NOTYPE)) continue;
        elfsym_t tmp;
        tmp.name = strdup(strtab + s->st_name);
        tmp.value = s->st_value;
        tmp.size = s->st_size;
        m->syms = (elfsym_t*)realloc(m->syms, (m->nsyms + 1) * sizeof(*m->syms));
        if (!m->syms) return;
        m->syms[m->nsyms++] = tmp;
    }
}

static int load_elf_module(elfsym_mod_t *m, uint64_t map_start, size_t map_off) {
    int fd = open(m->path, O_RDONLY);
    if (fd < 0) return -1;

    Elf64_Ehdr eh;
    if (pread(fd, &eh, sizeof(eh), 0) != (ssize_t)sizeof(eh)) { close(fd); return -1; }
    if (memcmp(eh.e_ident, ELFMAG, SELFMAG) != 0) { close(fd); return -1; }
    if (eh.e_machine != EM_X86_64) { close(fd); return -1; }
    if (eh.e_type != ET_EXEC && eh.e_type != ET_DYN) { close(fd); return -1; }

    uint64_t load_base = map_start;
    if (eh.e_phoff && eh.e_phnum) {
        Elf64_Phdr *ph = (Elf64_Phdr*)malloc(eh.e_phnum * sizeof(Elf64_Phdr));
        if (ph) {
            ssize_t n = pread(fd, ph, eh.e_phnum * sizeof(Elf64_Phdr), eh.e_phoff);
            if (n == (ssize_t)(eh.e_phnum * sizeof(Elf64_Phdr))) {
                for (int i = 0; i < eh.e_phnum; i++) {
                    if (ph[i].p_type == PT_LOAD && (size_t)ph[i].p_offset == map_off) {
                        load_base = map_start - ph[i].p_vaddr;
                        break;
                    }
                }
            }
            free(ph);
        }
    }
    m->load_base = load_base;

    if (eh.e_shoff && eh.e_shnum) {
        Elf64_Shdr *sh = (Elf64_Shdr*)malloc(eh.e_shnum * sizeof(Elf64_Shdr));
        ssize_t got = pread(fd, sh, eh.e_shnum * sizeof(Elf64_Shdr), eh.e_shoff);
        if (got == (ssize_t)(eh.e_shnum * sizeof(Elf64_Shdr))) {
            for (int i = 0; i < eh.e_shnum; i++) {
                if (sh[i].sh_type != SHT_SYMTAB && sh[i].sh_type != SHT_DYNSYM) continue;
                if (sh[i].sh_entsize == 0) continue;
                if (sh[i].sh_link >= eh.e_shnum) continue;
                size_t nsyms = sh[i].sh_size / sh[i].sh_entsize;
                if (nsyms == 0) continue;
                Elf64_Sym *symtab = (Elf64_Sym*)malloc(sh[i].sh_size);
                char *strtab = NULL;
                size_t strsz = 0;
                if (symtab &&
                    pread(fd, symtab, sh[i].sh_size, sh[i].sh_offset) == (ssize_t)sh[i].sh_size) {
                    const Elf64_Shdr *strsh = &sh[sh[i].sh_link];
                    strsz = strsh->sh_size;
                    strtab = (char*)malloc(strsz);
                    if (strtab &&
                        pread(fd, strtab, strsz, strsh->sh_offset) != (ssize_t)strsz) {
                        free(strtab);
                        strtab = NULL;
                    }
                }
                if (symtab && strtab) add_symbols(m, symtab, nsyms, strtab, strsz);
                free(symtab);
                free(strtab);
            }
        }
        free(sh);
    }
    close(fd);

    if (m->nsyms) {
        qsort(m->syms, m->nsyms, sizeof(*m->syms), sym_cmp);
        return 0;
    }
    return -1;
}

int elfsym_init(pid_t pid) {
    elfsym_free();
    procmaps_iterator *it = parse_maps_live(pid);
    if (!it) return -1;
    procmaps_struct *map;
    while ((map = pmparser_next(it)) != NULL) {
        if (!map->is_x) continue;
        if (!map->pathname || !map->pathname[0]) continue;
        if (map->pathname[0] == '[') continue;              /* vdso, vsyscall, vvar */
        if (strncmp(map->pathname, "/memfd:", 7) == 0) continue;
        bool dup = false;
        for (size_t i = 0; i < g_nmods; i++) {
            if (strcmp(g_mods[i].path, map->pathname) == 0) { dup = true; break; }
        }
        if (dup) continue;
        if (g_nmods == g_cap) {
            g_cap = g_cap ? g_cap * 2 : 8;
            g_mods = (elfsym_mod_t*)realloc(g_mods, g_cap * sizeof(*g_mods));
            if (!g_mods) return -1;
        }
        elfsym_mod_t *m = &g_mods[g_nmods];
        memset(m, 0, sizeof(*m));
        m->path = strdup(map->pathname);
        m->start = (uint64_t)map->addr_start;
        m->end = (uint64_t)map->addr_end;
        if (load_elf_module(m, (uint64_t)map->addr_start, (size_t)map->offset) != 0) {
            free(m->path);
            continue;
        }
        g_nmods++;
    }
    pmparser_free(it);
    return g_nmods ? 0 : -1;
}

symres_t elfsym_resolve(uint64_t addr) {
    symres_t r = { 0 };
    for (size_t i = 0; i < g_nmods; i++) {
        elfsym_mod_t *m = &g_mods[i];
        if (addr < m->start || addr >= m->end) continue;
        uint64_t off = addr - m->load_base;
        int lo = -1, hi = (int)m->nsyms;
        while (hi - lo > 1) {
            int mid = (lo + hi) / 2;
            if (m->syms[mid].value <= off) lo = mid; else hi = mid;
        }
        if (lo >= 0) {
            uint64_t delta = off - m->syms[lo].value;
            bool ok = m->syms[lo].size ? (delta <= m->syms[lo].size)
                                       : (delta <= 0x1000);
            if (ok) {
                r.found = 1;
                r.name = m->syms[lo].name;
                r.delta = delta;
                return r;
            }
        }
    }
    return r;
}

void elfsym_free(void) {
    for (size_t i = 0; i < g_nmods; i++) {
        free(g_mods[i].path);
        for (size_t j = 0; j < g_mods[i].nsyms; j++) free(g_mods[i].syms[j].name);
        free(g_mods[i].syms);
    }
    free(g_mods);
    g_mods = NULL;
    g_nmods = 0;
    g_cap = 0;
}
