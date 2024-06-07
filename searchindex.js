Search.setIndex({"docnames": ["index", "security-spec", "tdx-guest-hardening"], "filenames": ["index.rst", "security-spec.rst", "tdx-guest-hardening.rst"], "titles": ["Intel\u00ae Trust Domain Extension Guest Kernel Hardening Documentation", "Intel\u00ae Trust Domain Extension Linux Guest Kernel Security Specification", "Intel\u00ae Trust Domain Extension Guest Linux Kernel Hardening Strategy"], "terms": {"linux": 0, "secur": [0, 2], "specif": [0, 2], "purpos": 0, "scope": 0, "threat": [0, 2], "model": [0, 2], "tdx": 0, "overal": [0, 2], "methodologi": [0, 2], "devic": 0, "filter": 0, "mechan": 0, "tdvmcall": [0, 2], "hypercal": [0, 2], "base": [0, 2], "commun": [0, 2], "interfac": [0, 2], "iommu": 0, "random": [0, 2], "insid": [0, 2], "tsc": 0, "other": [0, 2], "timer": 0, "declar": 0, "insecur": 0, "user": [0, 2], "space": 0, "bio": [0, 2], "suppli": [0, 2], "acpi": [0, 2], "tabl": [0, 2], "map": [0, 2], "privat": 0, "memori": [0, 2], "page": [0, 2], "manag": [0, 2], "reliabl": [0, 2], "panic": [0, 2], "initrd": [0, 2], "load": [0, 2], "command": [0, 2], "line": [0, 2], "storag": 0, "protect": [0, 2], "virtio": [0, 2], "share": 0, "transient": [0, 2], "execut": [0, 2], "attack": 0, "mitig": [0, 2], "summari": 0, "strategi": [0, 1], "overview": 0, "surfac": [0, 1], "minim": [0, 1], "static": [0, 1], "analyz": [0, 1], "code": 0, "audit": [0, 1], "td": [0, 1], "fuzz": [0, 1], "emul": [0, 1], "setup": [0, 1], "boot": [0, 1], "runtim": [0, 1], "enabl": [0, 1], "addit": [0, 1], "driver": 0, "celadon": [0, 1, 2], "movidiu": [0, 1, 2], "neural": [0, 1, 2], "network": [0, 1, 2], "nuc": [0, 1, 2], "platform": [0, 1, 2], "flash": [0, 1, 2], "tool": [0, 1, 2], "soc": [0, 1, 2], "watch": [0, 1, 2], "core": [0, 1, 2], "\u00b5": [0, 1, 2], "\u00b2": [0, 1, 2], "contributor": [1, 2], "andi": 1, "kleen": 1, "elena": [1, 2], "reshetova": [1, 2], "thi": [1, 2], "document": [1, 2], "describ": [1, 2], "architectur": [1, 2], "run": [1, 2], "The": [1, 2], "main": [1, 2], "goal": 1, "technologi": [1, 2], "i": [1, 2], "remov": [1, 2], "need": [1, 2], "virtual": [1, 2], "machin": [1, 2], "vmm": [1, 2], "It": [1, 2], "import": [1, 2], "note": [1, 2], "object": [1, 2], "uniqu": [1, 2], "common": [1, 2], "across": 1, "all": [1, 2], "confidenti": 1, "cloud": 1, "comput": 1, "solut": 1, "ccc": [1, 2], "amd": [1, 2], "sev": 1, "etc": [1, 2], "therefor": [1, 2], "mani": [1, 2], "aspect": [1, 2], "below": [1, 2], "applic": [1, 2], "tcb": 1, "sw": [1, 2], "stack": [1, 2], "shown": [1, 2], "figur": [1, 2], "1": [1, 2], "includ": [1, 2], "0": [1, 2], "major": [1, 2], "ar": [1, 2], "help": [1, 2], "prevent": [1, 2], "privileg": 1, "escal": 1, "well": [1, 2], "data": [1, 2], "integr": [1, 2], "violat": [1, 2], "untrust": [1, 2], "denial": 1, "servic": 1, "do": [1, 2], "toward": [1, 2], "out": [1, 2], "here": [1, 2], "sinc": [1, 2], "fulli": [1, 2], "under": [1, 2], "abl": [1, 2], "perform": 1, "default": [1, 2], "ensur": [1, 2], "regist": [1, 2], "howev": [1, 2], "thei": [1, 2], "cannot": [1, 2], "from": [1, 2], "leverag": [1, 2], "exist": [1, 2], "between": [1, 2], "primari": [1, 2], "hypervisor": [1, 2], "addition": [1, 2], "should": [1, 2], "ani": [1, 2], "new": [1, 2], "vector": [1, 2], "introduc": 1, "ring": [1, 2], "userspac": [1, 2], "3": [1, 2], "omit": 1, "doe": [1, 2], "address": [1, 2], "made": [1, 2], "possibl": [1, 2], "directli": [1, 2], "us": [1, 2], "abov": [1, 2], "mention": [1, 2], "expos": [1, 2], "an": [1, 2], "For": [1, 2], "exampl": 1, "debug": [1, 2], "test": [1, 2], "read": [1, 2], "own": [1, 2], "carefulli": 1, "valid": [1, 2], "input": [1, 2], "come": [1, 2], "also": [1, 2], "assum": [1, 2], "qemu": [1, 2], "As": [1, 2], "result": 1, "anoth": [1, 2], "potenti": [1, 2], "cover": [1, 2], "abus": 1, "printout": 1, "routin": [1, 2], "can": [1, 2], "now": [1, 2], "take": [1, 2], "paramet": [1, 2], "name": [1, 2], "descript": [1, 2], "link": [1, 2], "detail": 1, "nrdd": 1, "non": [1, 2], "robust": [1, 2], "malici": [1, 2], "portio": [1, 2], "sharedmemori": 1, "dma": 1, "consum": [1, 2], "disabl": 1, "most": [1, 2], "limit": [1, 2], "__init": 1, "function": 1, "some": [1, 2], "might": [1, 2], "legaci": [1, 2], "registr": [1, 2], "avoid": [1, 2], "set": [1, 2], "allow": [1, 2], "typic": [1, 2], "beyond": [1, 2], "first": [1, 2], "presenc": [1, 2], "see": [1, 2], "nrddi": 1, "l": [1, 2], "": [1, 2], "initi": [1, 2], "5": [1, 2], "15": [1, 2], "198": 1, "5198": 1, "locat": [1, 2], "restrict": [1, 2], "opt": 1, "provid": [1, 2], "onli": [1, 2], "rang": [1, 2], "0x40000000": 1, "0x400000ff": 1, "_": 1, "nrckc": 1, "complex": [1, 2], "requir": 1, "straightforward": [1, 2], "defens": 1, "depth": 1, "reli": 1, "open": [1, 2], "especi": 1, "tbd": [1, 2], "hcsg": 1, "gadget": [1, 2], "condit": [1, 2], "break": 1, "vm": [1, 2], "remain": [1, 2], "identifi": 1, "fix": 1, "them": [1, 2], "nraa": 1, "aml": 1, "interpret": [1, 2], "via": [1, 2], "fw": 1, "measur": [1, 2], "attest": [1, 2], "part": [1, 2], "remot": [1, 2], "even": [1, 2], "benign": [1, 2], "look": [1, 2], "exploit": 1, "unknown": 1, "bug": [1, 2], "There": [1, 2], "55": 1, "contain": [1, 2], "lot": 1, "enforc": 1, "firmwar": [1, 2], "hcr": 1, "observ": [1, 2], "affect": [1, 2], "state": [1, 2], "due": [1, 2], "being": [1, 2], "sourc": [1, 2], "entropi": 1, "cryptograph": 1, "output": [1, 2], "rdrand": 1, "rdseed": 1, "fallback": 1, "jiffi": 1, "hct": 1, "time": [1, 2], "modifi": [1, 2], "visibl": 1, "depend": [1, 2], "rollback": 1, "which": [1, 2], "guarante": [1, 2], "inject": [1, 2], "post": [1, 2], "except": [1, 2], "30": 1, "nmi": 1, "assist": [1, 2], "lipc": 1, "p": 1, "lost": 1, "ipi": 1, "drop": [1, 2], "vcpu": [1, 2], "attempt": 1, "caus": [1, 2], "unexpect": 1, "behavior": 1, "consequ": [1, 2], "find": 1, "so": 1, "far": [1, 2], "seem": 1, "safe": [1, 2], "n": 1, "A": [1, 2], "systemat": 1, "relev": [1, 2], "principl": [1, 2], "case": [1, 2], "corrupt": 1, "event": [1, 2], "safest": 1, "rais": 1, "when": [1, 2], "found": [1, 2], "section": [1, 2], "our": [1, 2], "analysi": [1, 2], "ha": [1, 2], "biggest": [1, 2], "more": [1, 2], "than": [1, 2], "95": 1, "everi": [1, 2], "valu": [1, 2], "malform": [1, 2], "fortun": [1, 2], "small": [1, 2], "subset": 1, "oper": [1, 2], "refer": [1, 2], "creat": [1, 2], "defin": [1, 2], "deni": 1, "author": [1, 2], "init": [1, 2], "automat": [1, 2], "msi": 1, "mailbox": 1, "latter": [1, 2], "ones": [1, 2], "pci_iomap_": 1, "devm_ioremap": 1, "plain": 1, "ioremap_": 1, "style": [1, 2], "either": [1, 2], "ioremap_driver_harden": 1, "manual": 1, "how": [1, 2], "activ": [1, 2], "If": [1, 2], "associ": 1, "desir": [1, 2], "pleas": [1, 2], "consult": [1, 2], "chang": [1, 2], "configur": [1, 2], "e": [1, 2], "In": [1, 2], "deploy": [1, 2], "current": [1, 2], "usag": [1, 2], "let": 1, "correspond": [1, 2], "must": [1, 2], "authoris": 1, "its": [1, 2], "happen": [1, 2], "done": [1, 2], "follow": [1, 2], "attribut": 1, "authorize_allow_dev": 1, "ven_id": 1, "dev_id": 1, "type": [1, 2], "pci_iomap": 1, "work": [1, 2], "fine": 1, "ioremap": 1, "won": 1, "t": [1, 2], "altern": [1, 2], "dedic": [1, 2], "explicitli": 1, "indic": [1, 2], "similar": [1, 2], "withstand": 1, "moreov": [1, 2], "place": [1, 2], "manipul": 1, "where": [1, 2], "level": [1, 2], "encrypt": 1, "authent": 1, "try": [1, 2], "craft": 1, "respons": [1, 2], "while": [1, 2], "portion": 1, "mainli": [1, 2], "pass": [1, 2], "instead": [1, 2], "insert": [1, 2], "path": [1, 2], "within": [1, 2], "handler": [1, 2], "central": 1, "invoc": [1, 2], "invok": [1, 2], "boost": 1, "certain": [1, 2], "hot": 1, "action": 1, "decod": 1, "instruct": 1, "standard": 1, "x86": [1, 2], "convert": [1, 2], "reject": 1, "implement": 1, "simpl": 1, "actual": [1, 2], "special": [1, 2], "fast": [1, 2], "iomap": 1, "critic": 1, "we": [1, 2], "care": 1, "about": [1, 2], "By": [1, 2], "region": 1, "resid": [1, 2], "To": [1, 2], "framework": 1, "inform": [1, 2], "gener": [1, 2], "h": [1, 2], "macro": [1, 2], "portabl": 1, "known": [1, 2], "direct": [1, 2], "spars": 1, "those": [1, 2], "__iomem": 1, "annot": 1, "support": [1, 2], "sigsegv": 1, "x2apic": 1, "mode": [1, 2], "xapic": 1, "vapic": 1, "later": [1, 2], "consid": [1, 2], "group": [1, 2], "10": 1, "9": 1, "both": [1, 2], "drastic": 1, "reduc": [1, 2], "rest": 1, "receiv": [1, 2], "trigger": [1, 2], "icr": 1, "deliveri": 1, "get": [1, 2], "make": [1, 2], "sure": [1, 2], "miss": [1, 2], "stop": [1, 2], "timeout": [1, 2], "alreadi": [1, 2], "normal": [1, 2], "smp_call_funct": 1, "apart": 1, "initcal": 1, "unauthor": 1, "error": [1, 2], "sever": [1, 2], "entiti": 1, "enumer": 1, "cf8": 1, "mcfg": 1, "impli": [1, 2], "256": 1, "byte": [1, 2], "been": [1, 2], "bridg": 1, "process": [1, 2], "verifi": [1, 2], "have": [1, 2], "techniqu": [1, 2], "paid": 1, "attent": 1, "overlap": 1, "each": [1, 2], "interact": [1, 2], "veri": [1, 2], "sysf": 1, "dev": [1, 2], "mem": 1, "could": [1, 2], "hole": 1, "pars": [1, 2], "sy": [1, 2], "bu": [1, 2], "degre": 1, "But": 1, "like": [1, 2], "operm": 1, "iopl": 1, "former": 1, "becaus": [1, 2], "forward": 1, "request": [1, 2], "came": 1, "go": 1, "prepar": 1, "pcie": 1, "nearli": 1, "arch": [1, 2], "asm": 1, "index": [1, 2], "alias": 1, "perf_ev": 1, "cpu": [1, 2], "resctrl": 1, "intern": [1, 2], "c": [1, 2], "two": [1, 2], "write": [1, 2], "side": 1, "channel": 1, "relat": [1, 2], "arch_cap": 1, "disallow": 1, "gp": 1, "upon": 1, "ia32_vmx_": 1, "18": 1, "exact": [1, 2], "back": [1, 2], "obtain": [1, 2], "reason": [1, 2], "context": [1, 2], "switch": [1, 2], "risk": 1, "issu": [1, 2], "low": [1, 2], "mask": 1, "individu": [1, 2], "bit": [1, 2], "save": [1, 2], "restor": [1, 2], "rather": 1, "ia32_mc": 1, "ia32_mtrr_": 1, "ia32_tme_": 1, "clear": [1, 2], "dure": [1, 2], "earli": [1, 2], "x86_feature_mc": [1, 2], "x86_feature_mtrr": [1, 2], "x86_feature_tm": [1, 2], "full": [1, 2], "up": [1, 2], "date": [1, 2], "tdx_early_init": 1, "approach": [1, 2], "respect": [1, 2], "ll": 1, "old": 1, "isa": 1, "vulner": 1, "auto": 1, "compil": [1, 2], "would": [1, 2], "promin": 1, "serial": 1, "g": [1, 2], "consol": [1, 2], "show": 1, "intend": 1, "comment": [1, 2], "0x70": 1, "0x71": 1, "mc146818": 1, "rtc": 1, "0xcf8": 1, "0xcff": 1, "ideal": [1, 2], "further": [1, 2], "0x600": 1, "0x62f": 1, "0600": 1, "0603": 1, "pm1a_evt_blk": 1, "0604": 1, "0605": 1, "pm1a_cnt_blk": 1, "0608": 1, "060b": 1, "pm_tmr": 1, "0620": 1, "062f": 1, "gpe0_blk": 1, "0x3f8": 1, "0x3f9": 1, "0x3fa": 1, "0x3fd": 1, "com1": 1, "debugmod": 1, "variou": [1, 2], "enhanc": [1, 2], "number": [1, 2], "pv": 1, "mean": [1, 2], "structur": [1, 2], "implic": 1, "kvm_feature_clocksourc": 1, "2": [1, 2], "kvmclock": 1, "explicit": 1, "indirectli": 1, "kvm_feature_async_pf": 1, "kvm_feature_pv_eoi": 1, "kvm_feature_steal_tim": 1, "td_param": 1, "logic": [1, 2], "leaf": 1, "0x2": 1, "cach": 1, "tlb": 1, "info": [1, 2], "obsolet": 1, "prefer": 1, "0x4": 1, "0x5": 1, "monitor": [1, 2], "mwait": 1, "0x6": 1, "thermal": 1, "power": 1, "mgmt": 1, "0x9": 1, "0xb": 1, "extend": [1, 2], "topologi": 1, "0xc": 1, "reserv": [1, 2], "Not": 1, "0xf": 1, "qo": 1, "x86_feature_cqm_llc": [1, 2], "0x10": 1, "x86_feature_mba": 1, "0x16": 1, "processor": 1, "frequenc": 1, "cpu_khz_from_cpuid": 1, "0x15": 1, "0x17": 1, "identif": 1, "0x18": 1, "determinist": 1, "0x1a": 1, "hybrid": 1, "0x1b": 1, "mk": 1, "tme": 1, "0x1f": [1, 2], "v2": 1, "0x80000002": 1, "4": [1, 2], "brand": 1, "string": [1, 2], "0x80000005": 1, "0x80000006": 1, "0x80000007": 1, "advanc": [1, 2], "differ": 1, "harmless": 1, "larger": 1, "field": 1, "same": 1, "wai": [1, 2], "sanit": [1, 2], "multi": 1, "expect": [1, 2], "given": [1, 2], "strengthen": 1, "recent": [1, 2], "tri": 1, "return": [1, 2], "uncor": 1, "don": 1, "kind": [1, 2], "chassi": 1, "discoveri": 1, "dmar": 1, "problem": [1, 2], "outsid": [1, 2], "commit": [1, 2], "coco": 1, "seed": 1, "system": [1, 2], "unless": [1, 2], "mix": 1, "pool": 1, "synchron": 1, "monoton": 1, "necessarili": [1, 2], "match": [1, 2], "real": [1, 2], "turn": 1, "truli": 1, "wall": 1, "server": 1, "recommend": [1, 2], "absenc": [1, 2], "yet": [1, 2], "present": [1, 2], "prioriti": 1, "anymor": [1, 2], "watchdog": 1, "forc": 1, "x86_feature_tsc_reli": 1, "influenc": 1, "deadlin": 1, "ecx": 1, "24": [1, 2], "report": [1, 2], "nativ": [1, 2], "msr_ia32_tsc_deadlin": 1, "subsequ": [1, 2], "On": [1, 2], "call": [1, 2], "start": [1, 2], "lapic": 1, "expir": 1, "argument": [1, 2], "detect": [1, 2], "mai": [1, 2], "continu": [1, 2], "fail": [1, 2], "taint": [1, 2], "flag": [1, 2], "taint_conf_no_lockdown": 1, "overrid": [1, 2], "lockdown": 1, "agent": 1, "proc": 1, "warn": [1, 2], "print": 1, "whenev": [1, 2], "overridden": 1, "over": [1, 2], "kei": [1, 2], "binari": [1, 2], "sign": [1, 2], "ioremap_cach": 1, "never": 1, "order": [1, 2], "ioremap_cache_shar": 1, "acpi_ex_system_memory_space_handl": 1, "motiv": 1, "keep": [1, 2], "minimum": [1, 2], "amount": [1, 2], "content": [1, 2], "doesn": 1, "proven": 1, "too": 1, "intrus": 1, "mostli": 1, "understand": [1, 2], "what": [1, 2], "particular": [1, 2], "Then": 1, "concern": [1, 2], "method": [1, 2], "step": [1, 2], "xsdt": [1, 2], "facp": [1, 2], "dsdt": [1, 2], "fac": [1, 2], "svkl": [1, 2], "still": 1, "larg": [1, 2], "one": [1, 2], "cppc": 1, "throttl": 1, "futur": [1, 2], "task": [1, 2], "whole": [1, 2], "consider": 1, "effort": [1, 2], "left": 1, "add": [1, 2], "accept": [1, 2], "tdg": [1, 2], "again": 1, "zero": 1, "secret": 1, "per": [1, 2], "design": [1, 2], "16": 1, "alwai": [1, 2], "notif": [1, 2], "altogeth": 1, "uefi": 1, "pre": [1, 2], "next": [1, 2], "signific": [1, 2], "onc": [1, 2], "ept": [1, 2], "entri": [1, 2], "pend": 1, "befor": [1, 2], "move": 1, "accord": 1, "essenti": [1, 2], "doubl": 1, "chanc": 1, "ok": [1, 2], "sequenc": 1, "tdh": 1, "block": [1, 2], "track": [1, 2], "quickli": 1, "aug": 1, "goe": [1, 2], "previous": 1, "end": [1, 2], "had": 1, "re": [1, 2], "2mb": 1, "granular": 1, "bitmap": 1, "decompressor": 1, "chunk": 1, "One": [1, 2], "gap": 1, "syscal": [1, 2], "sysret": 1, "window": 1, "pointer": [1, 2], "explain": [1, 2], "Such": 1, "gpa": 1, "sept_ve_dis": 1, "excess": 1, "tdc": 1, "notify_en": 1, "situat": [1, 2], "occur": 1, "otherwis": 1, "forcefulli": 1, "regardless": 1, "although": 1, "basic": [1, 2], "effect": [1, 2], "choos": 1, "notifi": 1, "someth": 1, "wait": 1, "atom": 1, "reentri": 1, "startup": [1, 2], "script": [1, 2], "unencrypt": 1, "vfat": 1, "volum": [1, 2], "area": [1, 2], "stub": 1, "hash": [1, 2], "imag": 1, "unsaf": 1, "tdx_disable_filt": 1, "complet": [1, 2], "off": [1, 2], "arbitrari": 1, "quirk": [1, 2], "capabl": 1, "longer": 1, "unharden": 1, "becom": 1, "reachabl": [1, 2], "guard": 1, "cc_platform_ha": 1, "cc_attr_guest_device_filt": 1, "quot": [1, 2], "specifi": [1, 2], "product": 1, "high": [1, 2], "haven": 1, "ad": [1, 2], "tdx_allow_acpi": 1, "similarli": [1, 2], "after": [1, 2], "assess": 1, "strongli": [1, 2], "mce": 1, "unneed": [1, 2], "mca": 1, "hasn": 1, "oop": 1, "noearli": 1, "nommconf": 1, "clock": [1, 2], "trust_cpu": 1, "y": [1, 2], "drng": 1, "enough": [1, 2], "trust_bootload": 1, "credit": 1, "bootload": [1, 2], "add_bootloader_random": 1, "disk": [1, 2], "decid": [1, 2], "tenant": 1, "dmcrypt": 1, "luk": 1, "dm": 1, "retriev": 1, "decrypt": 1, "loader": [1, 2], "itself": [1, 2], "protocol": [1, 2], "custom": [1, 2], "succe": 1, "mount": [1, 2], "file": [1, 2], "scheme": 1, "format": 1, "local": [1, 2], "themselv": 1, "commonli": [1, 2], "swap": 1, "filesystem": [1, 2], "recomend": 1, "transfer": [1, 2], "tl": 1, "transmit": 1, "natur": [1, 2], "ssh": 1, "highli": 1, "queue": 1, "transport": [1, 2], "wa": [1, 2], "outlin": [1, 2], "split": 1, "virtqueu": 1, "without": [1, 2], "indirect": 1, "descriptor": 1, "modern": [1, 2], "discourag": 1, "built": [1, 2], "around": [1, 2], "organ": 1, "free": 1, "point": [1, 2], "higher": [1, 2], "net": [1, 2], "9p": [1, 2], "vsock": [1, 2], "virtio_to_cpu": 1, "wrapper": [1, 2], "instrument": [1, 2], "softwar": [1, 2], "awar": 1, "emploi": 1, "appropri": [1, 2], "guidanc": [1, 2], "develop": [1, 2], "class": 1, "who": 1, "offset": [1, 2], "specul": 1, "classic": 1, "o": [1, 2], "adversari": 1, "necessari": 1, "copi": 1, "term": 1, "boundari": 1, "wider": 1, "involv": [1, 2], "facilit": [1, 2], "smatch": 1, "check_spectr": [1, 2], "pattern": 1, "environment": [1, 2], "variabl": [1, 2], "prior": 1, "export": 1, "analyze_host_data": 1, "revert": 1, "origin": [1, 2], "induc": 1, "unset": 1, "tree": 1, "test_kernel": 1, "sh": [1, 2], "produc": [1, 2], "smatch_warn": [1, 2], "txt": [1, 2], "tsc_msr": 1, "191": 1, "cpu_khz_from_msr": 1, "freq_desc": 1, "muldiv": 1, "r": 1, "206": 1, "freq": 1, "207": 1, "second": [1, 2], "half": 1, "210": 1, "item": [1, 2], "determin": [1, 2], "fals": 1, "posit": 1, "process_smatch_output": [1, 2], "py": [1, 2], "adjust": [1, 2], "reflect": 1, "phase": [1, 2], "build": [1, 2], "aim": 1, "progress": [1, 2], "solid": 1, "foundat": 1, "industri": 1, "tama": 2, "lengyel": 2, "sebastian": 2, "osterlund": 2, "steffen": 2, "schulz": 2, "host": 2, "paravirt": 2, "port": 2, "io": 2, "achiev": 2, "against": 2, "handl": 2, "concret": 2, "compon": 2, "scenario": 2, "ultim": 2, "100": 2, "mere": 2, "best": 2, "knowledg": 2, "resourc": 2, "environ": 2, "successfulli": 2, "mvp": 2, "http": 2, "github": 2, "com": 2, "subsystem": 2, "guid": 2, "written": 2, "mind": 2, "togeth": 2, "encompass": 2, "three": 2, "parallel": 2, "contribut": 2, "target": 2, "campaign": 2, "decis": 2, "crucial": 2, "criteria": 2, "finish": 2, "success": 2, "chosen": 2, "coverag": 2, "reach": 2, "exercis": 2, "suffici": 2, "significantli": 2, "difficult": 2, "total": 2, "quantifi": 2, "neither": 2, "nor": 2, "life": 2, "cycl": 2, "much": 2, "stronger": 2, "albeit": 2, "factum": 2, "list": 2, "option": 2, "kvm": 2, "cpuid": 2, "virtio_net": 2, "virtio_consol": 2, "virtio_blk": 2, "9pnet_virtio": 2, "escap": 2, "util": 2, "decompress": 2, "tdvf": 2, "www": 2, "dam": 2, "extern": 2, "u": 2, "en": 2, "rev": 2, "pdf": 2, "rtmr": 2, "thu": 2, "big": 2, "predefin": 2, "apic": 2, "avail": 2, "sec": 2, "msr": 2, "through": 2, "codebas": 2, "fact": 2, "x86_feature_aperfmperf": 2, "miscellan": 2, "fake": 2, "id": 2, "leav": 2, "xen": 2, "hyperv": 2, "acrn": 2, "northbridg": 2, "accident": 2, "previou": 2, "unsecur": 2, "focus": 2, "easi": 2, "patch": 2, "1500": 2, "imposs": 2, "maintain": 2, "version": 2, "establish": 2, "easili": 2, "sourceforg": 2, "search": 2, "problemat": 2, "mainlin": 2, "smatch_kernel_host_data": 2, "native_read_msr": 2, "inb": 2, "w": 2, "readb": 2, "pci_read_config": 2, "pci_bu": 2, "user_read_": 2, "correct": 2, "mark": 2, "host_data": 2, "propag": 2, "benefit": 2, "correctli": 2, "spectr": 2, "v1": 2, "inabl": 2, "virtio16": 2, "32": 2, "64_to_cpu": 2, "irq": 2, "1201": 2, "pirq_enable_irq": 2, "9123410094849481700": 2, "pci_read_config_byt": 2, "int": 2, "pin": 2, "uchar": 2, "1216": 2, "11769853683657473858": 2, "express": 2, "io_apic_get_pci_irq_vector": 2, "1228": 2, "15187152360757797804": 2, "pci_swizzle_interrupt_pin": 2, "1229": 2, "8593519367775469163": 2, "1233": 2, "3245640912980979571": 2, "65": 2, "_dev_warn": 2, "1243": 2, "11844818720957432302": 2, "_dev_info": 2, "1262": 2, "14811741117821484023": 2, "sampl": 2, "store": 2, "snippet": 2, "highlight": 2, "precondit": 2, "cross": 2, "databas": 2, "least": 2, "6": 2, "header": 2, "repositori": 2, "autom": 2, "python": 2, "discard": 2, "sound": 2, "classifi": 2, "status": 2, "exclud": 2, "check": 2, "verif": 2, "none": 2, "unclassifi": 2, "caller": 2, "modul": 2, "challeng": 2, "categori": 2, "buffer": 2, "loop": 2, "iter": 2, "bound": 2, "anyth": 2, "els": 2, "partial": 2, "control": 2, "conceptu": 2, "kaslr": 2, "rc2": 2, "publish": 2, "baselin": 2, "vendor": 2, "suggest": 2, "procedur": 2, "analys": 2, "your": 2, "label": 2, "orang": 2, "djb2": 2, "rel": 2, "begin": 2, "improv": 2, "calcul": 2, "accuraci": 2, "project": 2, "were": 2, "catch": 2, "inde": 2, "practic": 2, "layer": 2, "review": 2, "hw": 2, "xeon": 2, "contrari": 2, "ahead": 2, "plai": 2, "role": 2, "shim": 2, "api": 2, "seam": 2, "wrap": 2, "vmx": 2, "lifecycl": 2, "destruct": 2, "seam_tdcreatevp": 2, "seam_tdinitvp": 2, "tdfreevp": 2, "seam_tdent": 2, "exit": 2, "exit_reason_tdcal": 2, "exit_reason_cpuid": 2, "exit_reason_ept_viol": 2, "ve": 2, "offici": 2, "adher": 2, "19": 2, "just": 2, "greater": 2, "0x80000000u": 2, "0x80000008u": 2, "seam_inject_v": 2, "usual": 2, "hard": 2, "adopt": 2, "feedback": 2, "bootstrap": 2, "combin": 2, "snapshot": 2, "flexibl": 2, "sub": 2, "recoveri": 2, "pio": 2, "7": 2, "final": 2, "crash": 2, "hang": 2, "rewrit": 2, "trap": 2, "feed": 2, "At": 2, "consist": 2, "helper": 2, "log": 2, "tdg_fuzz_en": 2, "tdg_fuzz_ev": 2, "paus": 2, "intellab": 2, "blob": 2, "tdx_fuzz": 2, "sequenti": 2, "payload": 2, "met": 2, "1e5206fbd6a3050c4b812a826de29982be7a5905": 2, "tdx_fuzz_ev": 2, "kasan_report": 2, "halt_loop": 2, "printk": 2, "collect": 2, "diagnost": 2, "immedi": 2, "earlyboot": 2, "post_trap": 2, "start_kernel": 2, "rest_init": 2, "do_bas": 2, "doinitcal": 2, "doinitcalls_pci": 2, "doinitcalls_virtio": 2, "doinitcalls_acpi": 2, "doinitcalls_level_x": 2, "full_boot": 2, "kretprob": 2, "singl": 2, "virtio_console_init": 2, "early_pci_serial_init": 2, "master": 2, "doc": 2, "boot_har": 2, "These": 2, "config_tdx_fuzz_harness_earlyboot": 2, "tdx_fuzz_en": 2, "reset": 2, "until": 2, "termin": 2, "edg": 2, "trace": 2, "extract": 2, "gather": 2, "stage": 2, "durat": 2, "select": 2, "you": 2, "want": 2, "doinitcalls_level_4": 2, "manner": 2, "view": 2, "kafl_gui": 2, "shm": 2, "user_tdfl": 2, "long": 2, "corpu": 2, "cov": 2, "_tdfl": 2, "directori": 2, "addr2lin": 2, "lst": 2, "idea": 2, "smatch_match": 2, "pt": 2, "augment": 2, "ghidra": 2, "use_ghidra": 2, "run_experi": 2, "multipl": 2, "program": 2, "good": 2, "obviou": 2, "downsid": 2, "labor": 2, "intens": 2, "scale": 2, "suit": 2, "eventu": 2, "ltp": 2, "netperf": 2, "stress": 2, "ng": 2, "perf": 2, "todo": 2, "put": 2, "usermod": 2, "programmat": 2, "lead": 2, "syzkal": 2, "bia": 2, "research": 2, "right": 2, "vp": 2, "vmcall": 2, "mutat": 2, "shift": 2, "algorithm": 2, "__tdx_fuzz": 2, "recov": 2, "statist": 2, "debugf": 2, "alloc": 2, "connect": 2, "captur": 2, "underpin": 2, "regular": 2, "ram": 2, "physic": 2, "mmu": 2, "translat": 2, "permiss": 2, "fault": 2, "bitdefend": 2, "vmi": 2, "introspect": 2, "breakpoint": 2, "unmap": 2, "frequent": 2, "taken": 2, "frame": 2, "four": 2, "top": 2, "whether": 2, "thread": 2, "stuck": 2, "shell": 2, "transplant": 2, "100k": 2, "250k": 2, "stacktrac": 2, "entir": 2, "4096": 2, "kasan": 2, "ubsan": 2, "wiki": 2, "earlier": 2, "setp": 2, "offer": 2, "harnes": 2, "rootf": 2, "config_tdx_fuzz_harness_non": 2, "launch": 2, "sharedir": 2, "download": 2, "driven": 2, "independ": 2, "adequ": 2, "bash": 2, "sbin": 2, "act": 2, "intermedi": 2, "frontend": 2, "candid": 2, "signal": 2, "elf": 2, "bin": 2, "kafl_ctl": 2, "hget": 2, "fetch": 2, "echo": 2, "grep": 2, "redirect": 2, "hprintf": 2, "hcat": 2, "bkc": 2, "sophist": 2, "sharedir_templ": 2, "better": 2, "last": 2, "Its": 2, "abstract": 2, "vmw_vsock": 2, "virtio_transport": 2, "register_virtio_driv": 2, "kchecker": 2, "instanc": 2, "instal": 2, "folder": 2, "root": 2, "readm": 2, "md": 2, "smatch_script": 2, "driver_result": 2, "305": 2, "virtio_transport_tx_work": 2, "8890488479003397221": 2, "virtqueue_get_buf": 2, "pkt": 2, "struct": 2, "virtio_vsock_pkt": 2, "306": 2, "5556237559821482352": 2, "virtio_transport_free_pkt": 2, "375": 2, "virtio_vsock_update_guest_cid": 2, "7572251756130242": 2, "guest_cid": 2, "377": 2, "16638257021812442297": 2, "410": 2, "virtio_transport_event_work": 2, "virtio_vsock_ev": 2, "412": 2, "8840682050757106252": 2, "virtio_vsock_event_handl": 2, "414": 2, "83481497696856778": 2, "virtio_vsock_event_fill_on": 2, "541": 2, "virtio_transport_rx_work": 2, "8890488479003397230": 2, "551": 2, "5556237559821482370": 2, "556": 2, "5857033014461230228": 2, "virtio_transport_deliver_tap_pkt": 2, "557": 2, "8453424129492944817": 2, "virtio_transport_recv_pkt": 2, "kfx": 2, "chain": 2, "divid": 2, "probe": 2, "easiest": 2, "creation": 2, "separ": 2, "benefici": 2, "hit": 2, "consumpt": 2, "discov": 2, "modif": 2, "opposit": 2, "nutshel": 2, "socket": 2, "modprob": 2, "vhost_vsock": 2, "config_vhost_vsock": 2, "shall": 2, "appear": 2, "vhost": 2, "insuffici": 2, "chmod": 2, "0666": 2, "append": 2, "pci0": 2, "cid": 2, "word": 2, "worker": 2, "syntax": 2, "magic": 2, "kafl_config": 2, "yaml": 2, "bkc_root": 2, "qemu_bas": 2, "qemu_id": 2, "evalu": 2, "plu": 2, "socat": 2, "dest": 2, "unreach": 2, "org": 2, "listen": 2, "8089": 2, "fork": 2, "summar": 2, "config_virtio_vsocket": 2, "thing": 2, "easier": 2, "busybox": 2, "cpio": 2, "gz": 2, "br2_package_socat": 2, "buildroot": 2, "2021": 2, "11": 2, "menuconfig": 2, "navig": 2, "menu": 2, "edit": 2, "harness_non": 2, "p1": 2, "text": 2, "stabl": 2, "encount": 2, "slightli": 2, "kafl_fuzz": 2, "assign": 2, "overwrit": 2, "true": 2, "demonstr": 2, "reproduc": 2, "investig": 2, "encourag": 2, "submit": 2, "everyon": 2, "joint": 2, "round": 2, "alexand": 2, "shishkin": 2, "uapi": 2, "virtio_id": 2, "diff": 2, "git": 2, "b": 2, "47fda826aec4": 2, "fd759680bd2a": 2, "100644": 2, "64": 2, "pci_device_id": 2, "pci_allow_id": 2, "pci_devic": 2, "pci_vendor_id_redhat_qumranet": 2, "virtio1_id_block": 2, "virtio1_id_consol": 2, "virtio1_id_9p": 2, "virtio1_id_vsock": 2, "a2fcb4681028": 2, "f592efd82450": 2, "88": 2, "0x1042": 2, "transit": 2, "0x1043": 2, "0x1049": 2, "0x1053": 2, "endif": 2, "_linux_virtio_ids_h": 2, "25": 2}, "objects": {}, "objtypes": {}, "objnames": {}, "titleterms": {"intel": [0, 1, 2], "trust": [0, 1, 2], "domain": [0, 1, 2], "extens": [0, 1, 2], "guest": [0, 1, 2], "kernel": [0, 1, 2], "harden": [0, 1, 2], "document": 0, "linux": [1, 2], "secur": 1, "specif": 1, "purpos": [1, 2], "scope": [1, 2], "threat": 1, "model": 1, "tdx": [1, 2], "mitig": 1, "matrix": 1, "overal": 1, "methodologi": 1, "devic": [1, 2], "filter": [1, 2], "mechan": [1, 2], "passthrough": 1, "tdvmcall": 1, "hypercal": 1, "base": 1, "commun": 1, "interfac": 1, "mmio": [1, 2], "user": 1, "interrupt": 1, "handl": 1, "apic": 1, "pci": [1, 2], "config": [1, 2], "space": [1, 2], "subsystem": 1, "probe": 1, "driver": [1, 2], "alloc": 1, "resourc": 1, "program": 1, "access": [1, 2], "msr": 1, "control": 1, "modul": 1, "proxi": 1, "through": 1, "host": 1, "io": 1, "port": 1, "list": 1, "kvm": 1, "cpuid": 1, "featur": [1, 2], "leav": 1, "perfmon": 1, "iommu": 1, "random": 1, "insid": 1, "rng": 1, "tsc": 1, "other": 1, "timer": 1, "declar": 1, "insecur": 1, "bio": 1, "suppli": 1, "acpi": 1, "tabl": 1, "map": 1, "privat": 1, "memori": 1, "page": 1, "manag": 1, "tdvf": 1, "convers": 1, "lazi": 1, "safeti": 1, "against": 1, "ve": 1, "code": [1, 2], "reliabl": 1, "panic": 1, "initrd": 1, "load": 1, "command": 1, "line": 1, "cmdline": 1, "option": 1, "storag": 1, "protect": 1, "virtio": 1, "share": [1, 2], "transient": 1, "execut": 1, "attack": [1, 2], "bound": 1, "check": 1, "bypass": 1, "spectr": 1, "v1": 1, "summari": 1, "strategi": 2, "overview": 2, "surfac": 2, "minim": 2, "implement": 2, "statu": 2, "explicitli": 2, "disabl": 2, "function": 2, "opt": 2, "region": 2, "static": 2, "analyz": 2, "audit": 2, "requir": 2, "goal": 2, "check_host_input": 2, "smatch": 2, "pattern": 2, "perform": 2, "manual": 2, "find": 2, "appli": 2, "result": 2, "differ": 2, "tree": 2, "td": 2, "fuzz": 2, "emul": 2, "setup": 2, "detail": 2, "boot": 2, "agent": 2, "har": 2, "definit": 2, "exampl": 2, "workflow": 2, "instruct": 2, "runtim": 2, "stimulu": 2, "simpl": 2, "fuzzer": 2, "hook": 2, "kf": 2, "x": 2, "dma": 2, "kafl": 2, "enabl": 2, "addit": 2, "identifi": 2, "pair": 2, "fix": 2}, "envversion": {"sphinx.domains.c": 2, "sphinx.domains.changeset": 1, "sphinx.domains.citation": 1, "sphinx.domains.cpp": 8, "sphinx.domains.index": 1, "sphinx.domains.javascript": 2, "sphinx.domains.math": 2, "sphinx.domains.python": 3, "sphinx.domains.rst": 2, "sphinx.domains.std": 2, "sphinx.ext.todo": 2, "sphinx": 57}, "alltitles": {"Intel\u00ae Trust Domain Extension Guest Kernel Hardening Documentation": [[0, "intel-trust-domain-extension-guest-kernel-hardening-documentation"]], "Intel\u00ae Trust Domain Extension Linux Guest Kernel Security Specification": [[1, "intel-trust-domain-extension-linux-guest-kernel-security-specification"]], "Purpose and Scope": [[1, "purpose-and-scope"], [2, "purpose-and-scope"]], "Threat model": [[1, "threat-model"]], "TDX guest Linux kernel threat mitigation matrix": [[1, "id8"]], "TDX Linux guest kernel overall hardening methodology": [[1, "tdx-linux-guest-kernel-overall-hardening-methodology"]], "Device filter mechanism": [[1, "device-filter-mechanism"]], "Device passthrough": [[1, "device-passthrough"]], "TDVMCALL-hypercall-based communication interfaces": [[1, "tdvmcall-hypercall-based-communication-interfaces"]], "MMIO": [[1, "mmio"]], "Kernel MMIO": [[1, "kernel-mmio"]], "User MMIO": [[1, "user-mmio"]], "Interrupt handling and APIC": [[1, "interrupt-handling-and-apic"]], "PCI config space": [[1, "pci-config-space"]], "PCI subsystem for probing drivers": [[1, "pci-subsystem-for-probing-drivers"]], "Allocating resources": [[1, "allocating-resources"]], "Drivers": [[1, "drivers"]], "User programs accessing PCI config space": [[1, "user-programs-accessing-pci-config-space"]], "MSRs": [[1, "msrs"]], "MSRs controlled by TDX module": [[1, "msrs-controlled-by-tdx-module"]], "MSRs proxied through TDVMCALL and controlled by host": [[1, "msrs-proxied-through-tdvmcall-and-controlled-by-host"]], "IO ports": [[1, "io-ports"]], "List ports": [[1, "id9"]], "KVM CPUID features and Hypercalls": [[1, "kvm-cpuid-features-and-hypercalls"]], "CPUID": [[1, "cpuid"]], "CPUID leaves": [[1, "id10"]], "Perfmon": [[1, "perfmon"]], "IOMMU": [[1, "iommu"]], "Randomness inside TDX guest": [[1, "randomness-inside-tdx-guest"]], "Linux RNG": [[1, "linux-rng"]], "TSC and other timers": [[1, "tsc-and-other-timers"]], "Declaring insecurity to user space": [[1, "declaring-insecurity-to-user-space"]], "BIOS-supplied ACPI tables and mappings": [[1, "bios-supplied-acpi-tables-and-mappings"]], "TDX guest private memory page management": [[1, "tdx-guest-private-memory-page-management"]], "TDVF conversion": [[1, "tdvf-conversion"]], "Lazy conversion": [[1, "lazy-conversion"]], "Safety against #VE in kernel code": [[1, "safety-against-ve-in-kernel-code"]], "Reliable panic": [[1, "reliable-panic"]], "Kernel and initrd loading": [[1, "kernel-and-initrd-loading"]], "Kernel command line": [[1, "kernel-command-line"]], "cmdline options": [[1, "id11"]], "Storage protection": [[1, "storage-protection"]], "VirtIO and shared memory": [[1, "virtio-and-shared-memory"]], "Transient Execution attacks and their mitigation": [[1, "transient-execution-attacks-and-their-mitigation"]], "Bounds Check Bypass (Spectre V1)": [[1, "bounds-check-bypass-spectre-v1"]], "Summary": [[1, "summary"]], "Intel\u00ae Trust Domain Extension Guest Linux Kernel Hardening Strategy": [[2, "intel-trust-domain-extension-guest-linux-kernel-hardening-strategy"]], "Hardening strategy overview": [[2, "hardening-strategy-overview"]], "Attack surface minimization": [[2, "attack-surface-minimization"]], "Implemented filtering mechanisms": [[2, "implemented-filtering-mechanisms"]], "Filter status": [[2, "id8"]], "Explicitly disabled functionality": [[2, "explicitly-disabled-functionality"]], "Features": [[2, "id9"]], "Opt-in shared MMIO regions & PCI config space access": [[2, "opt-in-shared-mmio-regions-pci-config-space-access"]], "Static Analyzer and Code Audit": [[2, "static-analyzer-and-code-audit"]], "Requirements and goals": [[2, "requirements-and-goals"]], "Check_host_input Smatch pattern": [[2, "check-host-input-smatch-pattern"]], "Performing a manual code audit": [[2, "performing-a-manual-code-audit"]], "Findings": [[2, "id10"]], "Applying code audit results to different kernel trees": [[2, "applying-code-audit-results-to-different-kernel-trees"]], "TD Guest Fuzzing": [[2, "td-guest-fuzzing"]], "TDX emulation setup": [[2, "tdx-emulation-setup"]], "Implementation details": [[2, "implementation-details"]], "Fuzzing Kernel Boot": [[2, "fuzzing-kernel-boot"]], "Agent": [[2, "agent"]], "Harnesses Definition": [[2, "harnesses-definition"]], "Example Workflow": [[2, "example-workflow"]], "Setup Instructions": [[2, "setup-instructions"]], "Fuzzing Kernel Runtime": [[2, "fuzzing-kernel-runtime"]], "Fuzzing Stimulus": [[2, "fuzzing-stimulus"]], "Simple Fuzzer Hooks": [[2, "simple-fuzzer-hooks"]], "KF/x DMA Fuzzing": [[2, "kf-x-dma-fuzzing"]], "Overview": [[2, "overview"]], "Details": [[2, "details"]], "Setup instructions": [[2, "id5"]], "kAFL Stimulus Fuzzing": [[2, "kafl-stimulus-fuzzing"]], "Harness Setup": [[2, "harness-setup"]], "Enabling additional kernel drivers": [[2, "enabling-additional-kernel-drivers"]], "Identify the device/driver pair": [[2, "identify-the-device-driver-pair"]], "Perform code audit": [[2, "perform-code-audit"]], "Perform driver fuzzing": [[2, "perform-driver-fuzzing"]], "Perform code fixes": [[2, "perform-code-fixes"]], "Enable driver in the TDX filter": [[2, "enable-driver-in-the-tdx-filter"]]}, "indexentries": {}})