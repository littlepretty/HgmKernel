// SPDX-License-Identifier: GPL-2.0-only
/*
 * arch/arm64/mm/hugetlbpage.c
 *
 * Copyright (C) 2013 Linaro Ltd.
 *
 * Based on arch/x86/mm/hugetlbpage.c.
 */

#include <linux/init.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/hugetlb.h>
#include <linux/pagemap.h>
#include <linux/err.h>
#include <linux/sysctl.h>
#include <asm/mman.h>
#include <asm/tlb.h>
#include <asm/tlbflush.h>

/*
 * HugeTLB Support Matrix
 *
 * ---------------------------------------------------
 * | Page Size | CONT PTE |  PMD  | CONT PMD |  PUD  |
 * ---------------------------------------------------
 * |     4K    |   64K    |   2M  |    32M   |   1G  |
 * |    16K    |    2M    |  32M  |     1G   |       |
 * |    64K    |    2M    | 512M  |    16G   |       |
 * ---------------------------------------------------
 */

/*
 * Reserve CMA areas for the largest supported gigantic
 * huge page when requested. Any other smaller gigantic
 * huge pages could still be served from those areas.
 */
#ifdef CONFIG_CMA
void __init arm64_hugetlb_cma_reserve(void)
{
	int order;

	if (pud_sect_supported())
		order = PUD_SHIFT - PAGE_SHIFT;
	else
		order = CONT_PMD_SHIFT - PAGE_SHIFT;

	/*
	 * HugeTLB CMA reservation is required for gigantic
	 * huge pages which could not be allocated via the
	 * page allocator. Just warn if there is any change
	 * breaking this assumption.
	 */
	WARN_ON(order <= MAX_ORDER);
	hugetlb_cma_reserve(order);
}
#endif /* CONFIG_CMA */

static bool __hugetlb_valid_size(unsigned long size)
{
	switch (size) {
#ifndef __PAGETABLE_PMD_FOLDED
	case PUD_SIZE:
		return pud_sect_supported();
#endif
	case CONT_PMD_SIZE:
	case PMD_SIZE:
	case CONT_PTE_SIZE:
		return true;
	}

	return false;
}

#ifdef CONFIG_ARCH_ENABLE_HUGEPAGE_MIGRATION
bool arch_hugetlb_migration_supported(struct hstate *h)
{
	size_t pagesize = huge_page_size(h);

	if (!__hugetlb_valid_size(pagesize)) {
		pr_warn("%s: unrecognized huge page size 0x%lx\n",
			__func__, pagesize);
		return false;
	}
	return true;
}
#endif

int pmd_huge(pmd_t pmd)
{
	return pmd_val(pmd) && !(pmd_val(pmd) & PMD_TABLE_BIT);
}

int pud_huge(pud_t pud)
{
#ifndef __PAGETABLE_PMD_FOLDED
	return pud_val(pud) && !(pud_val(pud) & PUD_TABLE_BIT);
#else
	return 0;
#endif
}

static int find_num_contig(struct mm_struct *mm, unsigned long addr,
			   const struct hugetlb_pte *hpte, size_t *pgsize)
{
	switch (hpte->level) {
		case HUGETLB_LEVEL_PMD:
			*pgsize = PMD_SIZE;
			BUG_ON(hugetlb_pte_size(hpte) != CONT_PMD_SIZE);
			return CONT_PMDS;
		case HUGETLB_LEVEL_PTE:
			*pgsize = PAGE_SIZE;
			BUG_ON(hugetlb_pte_size(hpte) != CONT_PTE_SIZE);
			return CONT_PTES;
		default:
			pr_err("find_num_contig got invalid hpte level :%d\n",
					hpte->level);
			BUG();
	}

	return 0;
}

static inline int num_contig_ptes(unsigned long size, size_t *pgsize)
{
	int contig_ptes = 0;

	*pgsize = size;

	switch (size) {
#ifndef __PAGETABLE_PMD_FOLDED
	case PUD_SIZE:
		if (pud_sect_supported())
			contig_ptes = 1;
		break;
#endif
	case PMD_SIZE:
		contig_ptes = 1;
		break;
	case CONT_PMD_SIZE:
		*pgsize = PMD_SIZE;
		contig_ptes = CONT_PMDS;
		break;
	case CONT_PTE_SIZE:
		*pgsize = PAGE_SIZE;
		contig_ptes = CONT_PTES;
		break;
	case PAGE_SIZE:
		contig_ptes = 1;
		break;
	}

	return contig_ptes;
}

pte_t hugetlb_pte_get(const struct hugetlb_pte *hpte)
{
	int ncontig, i;
	size_t pgsize;
	pte_t *ptep = hpte->ptep;
	pte_t orig_pte = ptep_get(ptep);

	if (!pte_present(orig_pte) || !pte_cont(orig_pte))
		return orig_pte;

	ncontig = num_contig_ptes(hugetlb_pte_size(hpte), &pgsize);
	for (i = 0; i < ncontig; i++, ptep++) {
		pte_t pte = ptep_get(ptep);

		if (pte_dirty(pte))
			orig_pte = pte_mkdirty(orig_pte);

		if (pte_young(pte))
			orig_pte = pte_mkyoung(orig_pte);
	}
	return orig_pte;
}

/*
 * Changing some bits of contiguous entries requires us to follow a
 * Break-Before-Make approach, breaking the whole contiguous set
 * before we can change any entries. See ARM DDI 0487A.k_iss10775,
 * "Misprogramming of the Contiguous bit", page D4-1762.
 *
 * This helper performs the break step.
 */
static pte_t get_clear_contig(struct mm_struct *mm,
			     unsigned long addr,
			     pte_t *ptep,
			     unsigned long pgsize,
			     unsigned long ncontig)
{
	pte_t orig_pte = ptep_get(ptep);
	unsigned long i;

	for (i = 0; i < ncontig; i++, addr += pgsize, ptep++) {
		pte_t pte = ptep_get_and_clear(mm, addr, ptep);

		/*
		 * If HW_AFDBM is enabled, then the HW could turn on
		 * the dirty or accessed bit for any page in the set,
		 * so check them all.
		 */
		if (pte_dirty(pte))
			orig_pte = pte_mkdirty(orig_pte);

		if (pte_young(pte))
			orig_pte = pte_mkyoung(orig_pte);
	}
	return orig_pte;
}

static pte_t get_clear_contig_flush(struct mm_struct *mm,
				    unsigned long addr,
				    pte_t *ptep,
				    unsigned long pgsize,
				    unsigned long ncontig)
{
	pte_t orig_pte = get_clear_contig(mm, addr, ptep, pgsize, ncontig);
	struct vm_area_struct vma = TLB_FLUSH_VMA(mm, 0);

	flush_tlb_range(&vma, addr, addr + (pgsize * ncontig));
	return orig_pte;
}

/*
 * Changing some bits of contiguous entries requires us to follow a
 * Break-Before-Make approach, breaking the whole contiguous set
 * before we can change any entries. See ARM DDI 0487A.k_iss10775,
 * "Misprogramming of the Contiguous bit", page D4-1762.
 *
 * This helper performs the break step for use cases where the
 * original pte is not needed.
 */
static void clear_flush(struct mm_struct *mm,
			     unsigned long addr,
			     pte_t *ptep,
			     unsigned long pgsize,
			     unsigned long ncontig)
{
	struct vm_area_struct vma = TLB_FLUSH_VMA(mm, 0);
	unsigned long i, saddr = addr;

	for (i = 0; i < ncontig; i++, addr += pgsize, ptep++)
		pte_clear(mm, addr, ptep);

	flush_tlb_range(&vma, saddr, addr);
}

static inline struct folio *hugetlb_swap_entry_to_folio(swp_entry_t entry)
{
	VM_BUG_ON(!is_migration_entry(entry) && !is_hwpoison_entry(entry));

	return page_folio(pfn_to_page(swp_offset_pfn(entry)));
}

void set_hugetlb_pte_at(struct mm_struct *mm, unsigned long addr,
			const struct hugetlb_pte *hpte, pte_t pte)
{
	size_t pgsize;
	int i;
	int ncontig;
	unsigned long pfn, dpfn;
	pgprot_t hugeprot;
	pte_t *ptep = hpte->ptep;

	if (!pte_present(pte)) {
		struct folio *folio;

		folio = hugetlb_swap_entry_to_folio(pte_to_swp_entry(pte));
		ncontig = num_contig_ptes(hugetlb_pte_size(hpte), &pgsize);

		for (i = 0; i < ncontig; i++, ptep++)
			set_pte_at(mm, addr, ptep, pte);
		return;
	}

	if (!pte_cont(pte)) {
		set_pte_at(mm, addr, ptep, pte);
		return;
	}

	ncontig = find_num_contig(mm, addr, hpte, &pgsize);
	pfn = pte_pfn(pte);
	dpfn = pgsize >> PAGE_SHIFT;
	hugeprot = pte_pgprot(pte);

	clear_flush(mm, addr, ptep, pgsize, ncontig);

	for (i = 0; i < ncontig; i++, ptep++, addr += pgsize, pfn += dpfn)
		set_pte_at(mm, addr, ptep, pfn_pte(pfn, hugeprot));
}

int hugetlb_walk_step(struct mm_struct *mm, struct hugetlb_pte *hpte,
		      unsigned long addr, unsigned long sz)
{
	unsigned int shift;
	unsigned long rounded_addr;
	pmd_t *cont_pmdp, cont_pmd;
	pmd_t *pmdp;
	pte_t *cont_ptep, cont_pte;
	pte_t *ptep;
	spinlock_t *ptl;

	switch(hpte->level) {
		case HUGETLB_LEVEL_PUD:
			rounded_addr = addr & CONT_PMD_MASK;
			pmdp = hugetlb_alloc_pmd(mm, hpte, addr);
			cont_pmdp = hugetlb_alloc_pmd(mm, hpte, rounded_addr);
			if (IS_ERR(pmdp))
				return PTR_ERR(pmdp);
			if (IS_ERR(cont_pmdp))
				return PTR_ERR(cont_pmdp);
			cont_pmd = READ_ONCE(*cont_pmdp);
			if ((pmd_present(cont_pmd) && pmd_cont(cont_pmd))
					|| sz == CONT_PMD_SIZE) {
				if (pmd_present(cont_pmd) && !pmd_cont(cont_pmd))
					return -EINVAL;
				shift = CONT_PMD_SHIFT;
				ptep = (pte_t *)cont_pmdp;
			} else {
				shift = PMD_SHIFT;
				ptep = (pte_t *)pmdp;
			}
			/*
			 * We must use the same PTL for contiguous and
			 * non-contiguous PMDs here.
			 */
			ptl = pmd_lockptr(mm, cont_pmdp);
			__hugetlb_pte_populate(hpte, ptep, shift,
					HUGETLB_LEVEL_PMD, ptl);
			break;
		case HUGETLB_LEVEL_PMD:
			/*
			 * If we are currently at CONT_PMD_SIZE, we need to
			 * first "walk" to PMD_SIZE. If we don't do this, we may
			 * turn the first PMD in the contiguous group into a
			 * non-leaf PMD, NOT the PMD we want.
			 */
			if (hpte->shift == CONT_PMD_SHIFT) {
				rounded_addr = addr & CONT_PMD_MASK;
				cont_pmdp = (pmd_t *)hpte->ptep;
				cont_pmd = READ_ONCE(*cont_pmdp);
				if (pmd_present(cont_pmd) && pmd_cont(cont_pmd))
					return -EEXIST;
				/* Find the PMD inside the cont PMD. */
				pmdp = &cont_pmdp[CONT_PMDS *
					(addr - rounded_addr)/CONT_PMD_SIZE];
				ptep = (pte_t *)pmdp;
				/*
				 * We mustn't change which PTL we are using, as
				 * we are not changing levels.
				 */
				ptl = hpte->ptl;
				__hugetlb_pte_populate(hpte, ptep, PMD_SHIFT,
						HUGETLB_LEVEL_PMD, ptl);
				break;
			}
			rounded_addr = addr & CONT_PTE_MASK;
			ptep = hugetlb_alloc_pte(mm, hpte, addr);
			cont_ptep = hugetlb_alloc_pte(mm, hpte, rounded_addr);
			if (IS_ERR(ptep))
				return PTR_ERR(ptep);
			if (IS_ERR(cont_ptep))
				return PTR_ERR(cont_ptep);
			cont_pte = READ_ONCE(*cont_ptep);
			if ((pte_present(cont_pte) && pte_cont(cont_pte))
					|| sz == CONT_PTE_SIZE) {
				if (pte_present(cont_pte) && !pte_cont(cont_pte))
					return -EINVAL;
				shift = CONT_PTE_SHIFT;
				ptep = cont_ptep;
			} else
				shift = PAGE_SHIFT;

			ptl = pte_lockptr(mm, (pmd_t *)hpte->ptep);
			__hugetlb_pte_populate(hpte, ptep, shift,
					HUGETLB_LEVEL_PTE, ptl);
			break;
		case HUGETLB_LEVEL_PTE:
			/*
			 * The only possible case is that we are stepping from
			 * CONT_PTE_SHIFT to PAGE_SHIFT.
			 */
			if (hpte->shift != CONT_PTE_SHIFT)
				return -EINVAL;
			rounded_addr = addr & CONT_PTE_MASK;
			cont_ptep = hpte->ptep;
			cont_pte = READ_ONCE(*cont_ptep);
			if (pte_present(cont_pte) && pte_cont(cont_pte))
				return -EEXIST;
			/* Find the PTE inside the cont PTE. */
			ptep = &cont_ptep[CONT_PTES *
				(addr - rounded_addr)/CONT_PTE_SIZE];
			/*
			 * We cannot change PTLs, as we are staying on the same
			 * level.
			 */
			ptl = hpte->ptl;
			__hugetlb_pte_populate(hpte, ptep, PAGE_SHIFT,
					       HUGETLB_LEVEL_PTE, ptl);
			break;
		default:
			BUG();
	}
	return 0;
}

pte_t *huge_pte_alloc(struct mm_struct *mm, struct vm_area_struct *vma,
		      unsigned long addr, unsigned long sz)
{
	pgd_t *pgdp;
	p4d_t *p4dp;
	pud_t *pudp;
	pmd_t *pmdp;
	pte_t *ptep = NULL;

	pgdp = pgd_offset(mm, addr);
	p4dp = p4d_offset(pgdp, addr);
	pudp = pud_alloc(mm, p4dp, addr);
	if (!pudp)
		return NULL;

	if (sz == PUD_SIZE) {
		ptep = (pte_t *)pudp;
	} else if (sz == (CONT_PTE_SIZE)) {
		pmdp = pmd_alloc(mm, pudp, addr);
		if (!pmdp)
			return NULL;

		WARN_ON(addr & (sz - 1));
		/*
		 * Note that if this code were ever ported to the
		 * 32-bit arm platform then it will cause trouble in
		 * the case where CONFIG_HIGHPTE is set, since there
		 * will be no pte_unmap() to correspond with this
		 * pte_alloc_map().
		 */
		ptep = pte_alloc_map(mm, pmdp, addr);
	} else if (sz == PMD_SIZE) {
		if (want_pmd_share(vma, addr) && pud_none(READ_ONCE(*pudp)))
			ptep = huge_pmd_share(mm, vma, addr, pudp);
		else
			ptep = (pte_t *)pmd_alloc(mm, pudp, addr);
	} else if (sz == (CONT_PMD_SIZE)) {
		pmdp = pmd_alloc(mm, pudp, addr);
		WARN_ON(addr & (sz - 1));
		return (pte_t *)pmdp;
	}

	return ptep;
}

pte_t *huge_pte_offset(struct mm_struct *mm,
		       unsigned long addr, unsigned long sz)
{
	pgd_t *pgdp;
	p4d_t *p4dp;
	pud_t *pudp, pud;
	pmd_t *pmdp, pmd;

	pgdp = pgd_offset(mm, addr);
	if (!pgd_present(READ_ONCE(*pgdp)))
		return NULL;

	p4dp = p4d_offset(pgdp, addr);
	if (!p4d_present(READ_ONCE(*p4dp)))
		return NULL;

	pudp = pud_offset(p4dp, addr);
	pud = READ_ONCE(*pudp);
	if (sz != PUD_SIZE && pud_none(pud))
		return NULL;
	/* hugepage or swap? */
	if (sz == PUD_SIZE)
		return (pte_t *)pudp;
	/* table; check the next level */

	if (sz == CONT_PMD_SIZE)
		addr &= CONT_PMD_MASK;

	pmdp = pmd_offset(pudp, addr);
	pmd = READ_ONCE(*pmdp);
	if (!(sz == PMD_SIZE || sz == CONT_PMD_SIZE) &&
	    pmd_none(pmd))
		return NULL;
	if (sz == PMD_SIZE || sz == CONT_PMD_SIZE)
		return (pte_t *)pmdp;

	if (sz == CONT_PTE_SIZE)
		return pte_offset_kernel(pmdp, (addr & CONT_PTE_MASK));

	return NULL;
}

unsigned long hugetlb_mask_last_page(struct hstate *h)
{
	unsigned long hp_size = huge_page_size(h);

	switch (hp_size) {
#ifndef __PAGETABLE_PMD_FOLDED
	case PUD_SIZE:
		return PGDIR_SIZE - PUD_SIZE;
#endif
	case CONT_PMD_SIZE:
		return PUD_SIZE - CONT_PMD_SIZE;
	case PMD_SIZE:
		return PUD_SIZE - PMD_SIZE;
	case CONT_PTE_SIZE:
		return PMD_SIZE - CONT_PTE_SIZE;
	default:
		break;
	}

	return 0UL;
}

pte_t arch_make_huge_pte(pte_t entry, unsigned int shift, vm_flags_t flags)
{
	size_t pagesize = 1UL << shift;

	if (pagesize == PAGE_SIZE)
		return entry;

	entry = pte_mkhuge(entry);

	if (pagesize == CONT_PTE_SIZE) {
		entry = pte_mkcont(entry);
	} else if (pagesize == CONT_PMD_SIZE) {
		entry = pmd_pte(pmd_mkcont(pte_pmd(entry)));
	} else if (pagesize != PUD_SIZE && pagesize != PMD_SIZE) {
		pr_warn("%s: unrecognized huge page size 0x%lx\n",
			__func__, pagesize);
	}
	return entry;
}

void hugetlb_pte_clear(struct mm_struct *mm, unsigned long addr,
		    const struct hugetlb_pte *hpte)
{
	int i, ncontig;
	size_t pgsize;
	pte_t *ptep = hpte->ptep;

	ncontig = num_contig_ptes(hugetlb_pte_size(hpte), &pgsize);

	for (i = 0; i < ncontig; i++, addr += pgsize, ptep++)
		pte_clear(mm, addr, ptep);
}

pte_t hugetlb_pte_get_and_clear(struct mm_struct *mm,
				unsigned long addr,
				const struct hugetlb_pte *hpte)
{
	int ncontig;
	size_t pgsize;
	pte_t orig_pte = ptep_get(hpte->ptep);

	if (!pte_cont(orig_pte))
		return ptep_get_and_clear(mm, addr, hpte->ptep);

	ncontig = find_num_contig(mm, addr, hpte, &pgsize);

	return get_clear_contig(mm, addr, hpte->ptep, pgsize, ncontig);
}

/*
 * hugetlb_pte_set_access_flags will update access flags (dirty, accesssed)
 * and write permission.
 *
 * For a contiguous huge pte range we need to check whether or not write
 * permission has to change only on the first pte in the set. Then for
 * all the contiguous ptes we need to check whether or not there is a
 * discrepancy between dirty or young.
 */
static int __cont_access_flags_changed(pte_t *ptep, pte_t pte, int ncontig)
{
	int i;

	if (pte_write(pte) != pte_write(ptep_get(ptep)))
		return 1;

	for (i = 0; i < ncontig; i++) {
		pte_t orig_pte = ptep_get(ptep + i);

		if (pte_dirty(pte) != pte_dirty(orig_pte))
			return 1;

		if (pte_young(pte) != pte_young(orig_pte))
			return 1;
	}

	return 0;
}

int hugetlb_pte_set_access_flags(struct vm_area_struct *vma,
			       unsigned long addr, const struct hugetlb_pte *hpte,
			       pte_t pte, int dirty)
{
	int ncontig, i;
	size_t pgsize = 0;
	unsigned long pfn = pte_pfn(pte), dpfn;
	struct mm_struct *mm = vma->vm_mm;
	pgprot_t hugeprot;
	pte_t orig_pte, *ptep = hpte->ptep;

	if (!pte_cont(pte))
		return ptep_set_access_flags(vma, addr, hpte->ptep, pte, dirty);

	ncontig = find_num_contig(mm, addr, hpte, &pgsize);
	dpfn = pgsize >> PAGE_SHIFT;

	if (!__cont_access_flags_changed(ptep, pte, ncontig))
		return 0;

	orig_pte = get_clear_contig_flush(mm, addr, ptep, pgsize, ncontig);

	/* Make sure we don't lose the dirty or young state */
	if (pte_dirty(orig_pte))
		pte = pte_mkdirty(pte);

	if (pte_young(orig_pte))
		pte = pte_mkyoung(pte);

	hugeprot = pte_pgprot(pte);
	for (i = 0; i < ncontig; i++, ptep++, addr += pgsize, pfn += dpfn)
		set_pte_at(mm, addr, ptep, pfn_pte(pfn, hugeprot));

	return 1;
}

void hugetlb_pte_set_wrprotect(struct mm_struct *mm,
			     unsigned long addr, const struct hugetlb_pte *hpte)
{
	unsigned long pfn, dpfn;
	pgprot_t hugeprot;
	int ncontig, i;
	size_t pgsize;
	pte_t pte, *ptep = hpte->ptep;

	if (!pte_cont(READ_ONCE(*ptep))) {
		ptep_set_wrprotect(mm, addr, ptep);
		return;
	}

	ncontig = find_num_contig(mm, addr, hpte, &pgsize);
	dpfn = pgsize >> PAGE_SHIFT;

	pte = get_clear_contig_flush(mm, addr, ptep, pgsize, ncontig);
	pte = pte_wrprotect(pte);

	hugeprot = pte_pgprot(pte);
	pfn = pte_pfn(pte);

	for (i = 0; i < ncontig; i++, ptep++, addr += pgsize, pfn += dpfn)
		set_pte_at(mm, addr, ptep, pfn_pte(pfn, hugeprot));
}

pte_t hugetlb_pte_clear_flush(struct vm_area_struct *vma,
			    unsigned long addr, const struct hugetlb_pte *hpte)
{
	struct mm_struct *mm = vma->vm_mm;
	size_t pgsize;
	int ncontig;
	pte_t *ptep = hpte->ptep;

	if (!pte_cont(READ_ONCE(*ptep)))
		return ptep_clear_flush(vma, addr, ptep);

	ncontig = find_num_contig(mm, addr, hpte, &pgsize);
	return get_clear_contig_flush(mm, addr, ptep, pgsize, ncontig);
}

static int __init hugetlbpage_init(void)
{
	if (pud_sect_supported())
		hugetlb_add_hstate(PUD_SHIFT - PAGE_SHIFT);

	hugetlb_add_hstate(CONT_PMD_SHIFT - PAGE_SHIFT);
	hugetlb_add_hstate(PMD_SHIFT - PAGE_SHIFT);
	hugetlb_add_hstate(CONT_PTE_SHIFT - PAGE_SHIFT);

	return 0;
}
arch_initcall(hugetlbpage_init);

bool __init arch_hugetlb_valid_size(unsigned long size)
{
	return __hugetlb_valid_size(size);
}
