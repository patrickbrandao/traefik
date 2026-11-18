# Fingerprinting em Servidores Proxy (HTTP/0.9–HTTP/3 & QUIC)

## Como funciona

Em um servidor proxy (reverso, forward, API gateway ou WAF), **fingerprinting de rede e aplicação** consiste em extrair metadados estruturais e comportamentais de cada camada da conexão — **IP/TCP/UDP → QUIC → TLS/mTLS → Framing HTTP (0.9, 1.0, 1.1, 2, 3) → Túneis/Subprotocolos → Upstream** — e reduzi-los a strings canônicas ou hashes comparáveis contra bases de clientes conhecidos (browsers, apps móveis, SDKs, `curl`, Go, scrapers, C2) e perfis de anomalia.

Em proxies modernos, nenhum fingerprint isolado basta: bibliotecas como `uTLS` e `curl-impersonate` imitam o `ClientHello` de um browser, mas frequentemente falham em reproduzir simultaneamente **TCP/UDP envelope + QUIC Transport Parameters + HTTP/2 ou HTTP/3 `SETTINGS` + compressão HPACK/QPACK + ordem de pseudo-headers + latência diferencial (RTT)**. O poder real do proxy está na **correlação cross-layer**.

### Regras críticas de implementação (válidas em todas as camadas)

- **Preservar a ordem exata da rede (wire order)**: cipher suites, extensões TLS, opções TCP, `SETTINGS` de HTTP/2 e HTTP/3, QUIC Transport Parameters, pseudo-headers e headers HTTP/1.x carregam entropia justamente na ordem em que foram serializados. Quando um formato ordena campos (ex.: `JA3N`, `JA4`), essa ordenação faz parte explícita da especificação para resistir à randomização.
- **Tratar GREASE corretamente**: tanto TLS ([RFC 8701](https://www.rfc-editor.org/rfc/rfc8701) — `0x0a0a`, `0x1a1a`, ..., `0xfafa`) quanto QUIC ([RFC 9000 §18.1](https://www.rfc-editor.org/rfc/rfc9000#section-18.1) — `27 + 31 * N`, e versões `0x?a?a?a?a`) e HTTP/3 ([RFC 9114 §7.2.8](https://www.rfc-editor.org/rfc/rfc9114#section-7.2.8) — `0x1f * N + 0x21` em frames, settings e unidirectional streams) injetam valores aleatórios por conexão. A maioria dos hashes canônicos descarta os *valores* GREASE, mas registra sua **presença/ausência** (clientes simples em Go/Python/Rust costumam não emitir GREASE de H3/QUIC, entregando que não são browsers reais).
- **Capturar antes da normalização da biblioteca**: structs de alto nível descartam ordem, casing, duplicatas, padding e frames de controle. Sempre que o dado não for exposto cru pela stack, é necessário interceptar os bytes brutos ou usar hooks de framing/tracing.
- **Separar sinal passivo de autenticação**: fingerprint é **sinal probabilístico de correlação e classificação**, sujeito a colisões, NAT/CGNAT, middleboxes corporativos e spoofing deliberado — nunca substitui credenciais ou mTLS criptográfico.

---

## Panorama geral: catálogo completo de fingerprints em um Proxy HTTP/QUIC

| Camada | Tipo / Formato | O que inspeciona | Protocolos onde se aplica | Direção no Proxy |
|---|---|---|---|---|
| **L3 (IP)** | **IP / `p0f` / `JA4L`** | `TTL` / `Hop Limit` inicial (SO e distância em saltos), `DF`, `IP ID`, bits `ECN`/`DSCP`, IPv6 `Flow Label`, Happy Eyeballs (corrida IPv4/IPv6) | Todos (TCP e UDP/QUIC) | Cliente ↔ Proxy / Proxy ↔ Upstream |
| **L4 (TCP)** | **`JA4T` / `JA4TS` / `p0f` / Akamai TCP** | `SYN` / `SYN-ACK`: `Window Size`, `MSS` (revela overhead de VPN/túnel), lista e ordem de TCP Options (`WScale`, `SACK`, `TS`, `TFO`, `MPTCP`), clock skew de timestamps | HTTP/0.9, 1.0, 1.1, 2 (`h2`/`h2c`) | Cliente → Proxy (`JA4T`) / Servidor (`JA4TS`) |
| **L4 (UDP)** | **UDP Envelope Fingerprint** | Tamanho exato do datagrama UDP `Initial` (>= 1200 B: 1200, 1252, 1350, 1472...), bits `ECN`, entropia de porta efêmera, rajadas GSO/GRO | gQUIC, QUIC v1/v2, HTTP/3 | Cliente → Proxy |
| **L4/L7 (Tempo)** | **`JA4L` / `JA4LS` & RTT Differential** | Latência de transporte (TCP `SYN` ou QUIC `Initial`) comparada ao RTT de TLS, HTTP/2 `PING` ou WebSocket para detectar proxies residenciais/SOCKS/túneis | Todos | Bidirecional |
| **L4.5 (gQUIC)** | **`CYU`** (Salesforce) | Versão gQUIC (`Q043`–`Q050`) + lista ordenada de tags do `CHLO` (`PAD`, `SNI`, `VER`, `CCS`, `UAID`, ...) em MD5 | Google QUIC legado | Cliente → Proxy |
| **L4.5 (QUIC)** | **QUIC Initial & Header Fingerprint** | Versão (`v1` `0x00000001`, `v2` `0x6b3343cf`), tamanhos de `DCID`/`SCID`, tamanho do Packet Number, coalescência `Initial`+`0-RTT`, fragmentação/padding de frames `CRYPTO` | IETF QUIC v1/v2 (HTTP/3) | Cliente → Proxy |
| **L4.5 (QUIC)** | **QUIC Transport Parameters (`0x0039`)** | Ordem e valores de `initial_max_data`, `initial_max_stream_data_*`, `initial_max_streams_*`, `max_idle_timeout`, `ack_delay_exponent`, `max_ack_delay`, `active_connection_id_limit`, `disable_active_migration`, `max_datagram_frame_size`, `grease_quic_bit`, `version_information` + GREASE | IETF QUIC v1/v2 (HTTP/3) | Cliente ↔ Proxy |
| **L5 (TLS)** | **`JA3` / `JA3N`** | MD5 de `legacy_version,ciphers,extensões,curvas,formatos_ponto` (`JA3` na ordem recebida; `JA3N` com extensões ordenadas para resistir à permutação do Chrome 110+) | HTTPS (TLS 1.0–1.3) e QUIC (TLS 1.3) | Cliente → Proxy |
| **L5 (TLS)** | **`JA4` (`t` e `q`)** | Prefixo (`t`=TCP, `q`=QUIC), versão TLS real (`supported_versions`), presença de SNI, contagem de ciphers/extensões, ALPN + SHA-256 truncado de ciphers ordenados e de extensões/signature algorithms ordenados | HTTPS (TCP) e HTTP/3 (QUIC) | Cliente → Proxy |
| **L5 (TLS Deep)** | **Extended ClientHello / PeetPrint** | Payloads internos omitidos por JA3/JA4: grupos em `key_share` (ex.: pós-quântico `X25519MLKEM768`), `compress_certificate` (brotli/zlib/zstd), `ALPS` (`application_settings`), `delegated_credentials`, `psk_key_exchange_modes`, `record_size_limit`, tamanho de `padding`, `legacy_record_version` e fragmentação de records TLS | HTTPS e QUIC | Cliente → Proxy |
| **L5 (ECH)** | **ECH / `JA4E`** | Extensão `encrypted_client_hello` (`0xfe0d`): suíte HPKE (KEM/KDF/AEAD), `config_id`, tamanho do payload cifrado, SNI público (*Outer*) vs *Inner ClientHello* (quando o proxy termina ECH) | TLS 1.3 (TCP e QUIC) | Cliente → Proxy |
| **L5 (Sessão)** | **TLS Resumption & `0-RTT`** | Uso de `legacy_session_id` (32 B em TLS 1.3 TCP vs 0 B obrigatório em QUIC), tickets PSK, ofuscação `ticket_age_add`, tentativa de `early_data` (`0-RTT`) e resposta a `HelloRetryRequest` | TLS 1.2/1.3 e QUIC | Cliente ↔ Proxy |
| **L5 (X.509)** | **`JA4X` & Cert/SPKI Pinning** | `JA4X`: estrutura do certificado (ordem de OIDs de Issuer, Subject e Extensões X.509v3). Pinning/Thumbprint: SHA-256 do DER ou `SubjectPublicKeyInfo` ([RFC 9440](https://www.rfc-editor.org/rfc/rfc9440)) | mTLS (cliente) e TLS (upstream) | Cliente → Proxy / Upstream → Proxy |
| **L5 (Server)** | **`JA3S` / `JA4S` (passivo) & `JARM` (ativo)** | `JA3S`/`JA4S`: `ServerHello` escolhido (versão, cipher, ordem de extensões). `JARM`: hash fuzzy das respostas a 10 sondas `ClientHello` ativas | TLS (TCP) e QUIC | Upstream → Proxy (ou scanners contra o Proxy) |
| **L7 (H0.9)** | **HTTP/0.9 Raw Wire** | Linha única `GET /path` sem versão nem headers, terminador `CRLF` vs `LF` puro, fechamento imediato | HTTP/0.9 | Cliente → Proxy |
| **L7 (H1.x)** | **`JA4H` & HTTP/1.x Sintático** | `JA4H` (método, versão `10`/`11`, flags `Cookie`/`Referer`, contagem, `Accept-Language`, SHA-256 de headers na ordem, nomes e valores de cookies ordenados) + **exclusivos de H1.x**: casing dos headers (`Sec-CH-UA` vs `sec-ch-ua`), espaços após `:`, posição de `Host`, `Connection`, hex de chunks (`Transfer-Encoding: chunked`), `origin-form` vs `absolute-form` | HTTP/1.0, HTTP/1.1 | Cliente → Proxy |
| **L7 (H2)** | **Akamai HTTP/2 Fingerprint & HPACK** | Frame `SETTINGS` (IDs, ordem e valores), `WINDOW_UPDATE` inicial na stream `0`, frames `PRIORITY` ([RFC 7540](https://www.rfc-editor.org/rfc/rfc7540)) / `PRIORITY_UPDATE` ([RFC 9218](https://www.rfc-editor.org/rfc/rfc9218)), ordem exata dos pseudo-headers (`:method`, `:authority`, `:scheme`, `:path`), indexação/Huffman no HPACK, `PING` e preface `h2c` | HTTP/2 (`h2` e `h2c`) | Cliente ↔ Proxy |
| **L7 (H3)** | **HTTP/3 Framing, `SETTINGS` & QPACK** | Ordem de abertura de unidirectional streams (`Control`, `QPACK Encoder/Decoder`, GREASE), `SETTINGS` H3 (`QPACK_MAX_TABLE_CAPACITY`, `MAX_FIELD_SECTION_SIZE`, `QPACK_BLOCKED_STREAMS`, `ENABLE_CONNECT_PROTOCOL`, `H3_DATAGRAM` + GREASE), frames GREASE, uso real de tabela dinâmica QPACK, ordem de pseudo-headers + `Priority` | HTTP/3 (`h3`) | Cliente ↔ Proxy |
| **L7 (Túneis)** | **Proxy / Tunnel / Upgrade Fingerprints** | `HTTP CONNECT` (headers pré-túnel como `Proxy-Connection`), Extended `CONNECT` (`:protocol`), `MASQUE` (`CONNECT-UDP` / `CONNECT-IP` + `Capsule-Protocol`), `WebSocket` (`permessage-deflate`, masking, ping), `gRPC` (`te: trailers`, `grpc-*`), TLVs de **PROXY Protocol v2** | HTTP/1.1, HTTP/2, HTTP/3 | Cliente ↔ Proxy ↔ Upstream |
| **Cross-Layer** | **Consistência Multi-Camada & `Alt-Svc`** | Coerência entre `User-Agent`/`Sec-CH-UA` ↔ `JA4` ↔ QUIC TP ↔ `H2/H3 SETTINGS` ↔ `JA4H` ↔ `JA4T`/`TTL`, migração `Alt-Svc` (TCP→QUIC) e padrão de multiplexação de streams | Todos combinados | Fim a fim no Proxy |

---

## Detalhamento por camada e versão de protocolo

### 1. Rede e Transporte (L3 / L4 — IP, TCP e UDP)

Mesmo antes de qualquer byte criptográfico, a pilha de sistema operacional do cliente deixa assinaturas fortes no socket de entrada do proxy:

- **IP (L3 — `p0f` / `JA4L`)**:
  - **`TTL` / `Hop Limit` inicial**: sistemas operacionais usam tetos padronizados (`64` em Linux/Android/macOS/iOS, `128` em Windows, `255` em equipamentos de rede). Subtraindo o `TTL` recebido do teto imediatamente superior estima-se a distância em roteadores (*hop count*); cruzando isso com um `User-Agent` que declara Windows (`TTL` esperado ~110–128) mas chega com `TTL=54` (teto 64, Linux), detecta-se spoofing de SO ou container de scraping.
  - **Flags e cabeçalho IP**: bit `DF` (*Don't Fragment*), padrão de incremento de `IP ID`, bits `ECN` (`ECT(0)`, `ECT(1)`) e `Flow Label` em IPv6, além da temporização de fallback IPv6→IPv4 (*Happy Eyeballs*, [RFC 8305](https://www.rfc-editor.org/rfc/rfc8305)).
- **TCP (L4 — `JA4T` / `JA4TS` / `p0f` v3)**: aplicável a `HTTP/0.9`, `HTTP/1.0`, `HTTP/1.1` e `HTTP/2`:
  - **`JA4T`** concatena `Window Size` inicial do `SYN` + lista ordenada na rede de códigos das TCP Options (ex.: `2-4-8-1-3` para `MSS`, `SACK Permitted`, `Timestamps`, `NOP`, `Window Scale`) + `MSS` + fator `Window Scale`.
  - **`MSS` reduzido** (ex.: `< 1460` em Ethernet padrão, como `1360`, `1380` ou `1420`) denuncia encapsulamento em **VPNs e túneis** (WireGuard, IPsec, OpenVPN, GRE, PPPoE, Cloudflare WARP).
  - **`JA4TS`** aplica a mesma lógica ao `SYN-ACK` (útil quando o proxy analisa upstreams ou detecta middleboxes TCP na frente dele).
- **UDP Envelope (L4 — exclusivo de QUIC / HTTP/3)**:
  - Como o QUIC roda sobre UDP, **não existe `SYN` nem `JA4T`**. Em vez disso, o proxy observa o **tamanho exato do primeiro datagrama UDP `Initial`** ([RFC 9000 §14.1](https://www.rfc-editor.org/rfc/rfc9000#section-14.1) exige mínimo de `1200` bytes, mas cada stack escolhe um teto distinto: `1200`, `1252`, `1350`, `1472`), marcação `ECN` no socket UDP, entropia de porta de origem e agrupamento de pacotes.
- **Latência e Distância Física (`JA4L` / `JA4LS` e RTT Differential)**:
  - Compara o RTT da camada de transporte (`SYN`→`ACK` no TCP, ou `Initial`→`Handshake` no QUIC) com o RTT da camada criptográfica/aplicação (tempo do voo final do TLS, `PING`→`PING ACK` do HTTP/2, ou ping de WebSocket).
  - **Detecção de Proxy Residencial / SOCKS5 / Forward Proxy**: quando um atacante usa um proxy intermediário, o handshake TCP/QUIC pode terminar num nó próximo ao servidor (RTT L4 de `2 ms`), enquanto os frames TLS ou HTTP/2 são retransmitidos até o cliente real do outro lado do mundo (RTT L7 de `180 ms`). Essa discrepância é um dos detectores mais eficazes de proxies de terceiros.

---

### 2. Camada QUIC (gQUIC, IETF QUIC v1 e QUIC v2)

Em proxies com suporte a HTTP/3, o transporte QUIC concentra boa parte dos sinais que antes ficavam divididos entre TCP e HTTP/2:

1. **gQUIC legado (`CYU`)**:
   - Criado pela Salesforce para o protocolo pré-IETF da Google (`Q043`, `Q046`, `Q050`). Calcula `MD5(versão,TAG1-TAG2-...)` do pacote `CHLO` em claro (tags como `PAD`, `SNI`, `STK`, `VER`, `CCS`, `UAID`, `TCID`, `ICSL`, `MIDS`). Hoje é histórico na web pública (substituído pelo IETF QUIC), mas ainda aparece em bases legadas de threat intelligence.
2. **Envelope do Pacote `Initial` IETF QUIC ([RFC 9000](https://www.rfc-editor.org/rfc/rfc9000) v1 / [RFC 9369](https://www.rfc-editor.org/rfc/rfc9369) v2)**:
   - Embora o pacote `Initial` seja protegido por AEAD, a chave é derivada deterministicamente do `DCID` enviado pelo próprio cliente usando um *salt* público da RFC ([RFC 9001 §5.2](https://www.rfc-editor.org/rfc/rfc9001#section-5.2)), permitindo a qualquer proxy que recebe o datagrama decodificá-lo integralmente.
   - Campos característicos: **versão QUIC** (`0x00000001` v1, `0x6b3343cf` v2, ou versões GREASE para testar Version Negotiation), **comprimentos exatos de `DCID` e `SCID`** (ex.: 8, 16 ou 20 bytes fixos por biblioteca), comprimento codificado do Packet Number (1, 2 ou 4 bytes), uso de **coalescência de pacotes** (`Initial` + `0-RTT` no mesmo datagrama UDP) e layout dos frames internos (ordem de `CRYPTO`, `PADDING` antes vs. depois do `CRYPTO`, ou `PING` intercalado — técnica comum em ferramentas anti-censura/DPI).
3. **QUIC Transport Parameters (Extensão TLS `0x0039` — [RFC 9000 §18](https://www.rfc-editor.org/rfc/rfc9000#section-18))**:
   - Transportados dentro do `ClientHello` TLS 1.3 do QUIC, funcionam como o equivalente direto de `TCP Options` + grande parte do `HTTP/2 SETTINGS`. Cada engine (Chromium/`quiche`, Firefox/`neqo`, Safari/`nw_quic`, `quic-go`, `quinn`, `msquic`, `aioquic`, `ngtcp2`) possui valores default e ordem de serialização muito distintos:
   - **Janelas de controle de fluxo**: `initial_max_data` (`0x04`), `initial_max_stream_data_bidi_local` (`0x05`), `initial_max_stream_data_bidi_remote` (`0x06`), `initial_max_stream_data_uni` (`0x07`).
   - **Concorrência de streams**: `initial_max_streams_bidi` (`0x08`), `initial_max_streams_uni` (`0x09`).
   - **Temporização e ACKs**: `max_idle_timeout` (`0x01`), `ack_delay_exponent` (`0x0a`), `max_ack_delay` (`0x0b`), `min_ack_delay` (`0xff04de1b` / draft).
   - **Capacidades e extensões**: `max_udp_payload_size` (`0x03`), `active_connection_id_limit` (`0x0e`), flag booleana `disable_active_migration` (`0x0c` — browsers móveis permitem migração Wi-Fi↔5G; servidores/CLI costumam desabilitar), `max_datagram_frame_size` (`0x20`, [RFC 9221](https://www.rfc-editor.org/rfc/rfc9221) — necessário para HTTP Datagrams, WebTransport e MASQUE), `grease_quic_bit` (`0x2ab2`, [RFC 9287](https://www.rfc-editor.org/rfc/rfc9287)), `version_information` (`0x11`, [RFC 9368](https://www.rfc-editor.org/rfc/rfc9368)), parâmetros proprietários (ex.: extensões Google `0x4752`...) e IDs GREASE (`27 + 31 * N`).
4. **Comportamento Dinâmico QUIC**:
   - Padrão de frames `ACK` (frequência e *ACK ranges*), perfil do controle de congestionamento e *pacing* (`CUBIC` vs `BBRv1`/`BBRv2`), tentativa de `0-RTT` e resposta a `PATH_CHALLENGE` / `PATH_RESPONSE` durante *NAT rebinding* ou migração de endereço.

---

### 3. Camada TLS e Certificados X.509 (TLS 1.0–1.3 sobre TCP e TLS 1.3 sobre QUIC)

- **`JA3` e `JA3N`**:
  - `JA3` gera o MD5 de `SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats` (valores decimais separados por `-`, sem GREASE). Como o Chrome 110+ passou a **permutar aleatoriamente a ordem das extensões TLS** a cada conexão, um mesmo browser gera bilhões de hashes `JA3` diferentes. O **`JA3N`** contorna isso ordenando numericamente a lista de extensões antes do MD5.
- **`JA4` (`a_b_c`)**:
  - Formato legível por humanos e resistente à randomização de extensões:
    - Parte `a` (10 chars): protocolo (`t` para TCP, `q` para QUIC, `d` para DTLS) + versão máxima real em `supported_versions` (`13`, `12`, `11`, `10`, `s3`, `s2`) + destino SNI (`d` domínio presente, `i` IP/ausente) + contagem de cipher suites (2 dígitos, sem GREASE) + contagem de extensões (2 dígitos, sem GREASE) + primeiro e último caractere do primeiro protocolo `ALPN` (`h2`, `h3`, `h1`, `00` se ausente).
    - Parte `b` (12 hex): primeiros 12 caracteres do SHA-256 dos cipher suites ordenados em hex (sem GREASE).
    - Parte `c` (12 hex): primeiros 12 caracteres do SHA-256 das extensões ordenadas em hex (sem GREASE, **excluindo** `SNI` `0x0000` e `ALPN` `0x0010`) concatenadas com `_` e os `signature_algorithms` na ordem original recebida.
- **Deep TLS Extension Fingerprinting (além do JA3/JA4 — estilo Cloudflare / Akamai / PeetPrint)**:
  - Como o `JA4` olha apenas os *IDs* das extensões e ordena-os, sistemas anti-bot modernos extraem também o **conteúdo interno** das extensões:
    - **`key_share` (`0x0033`)**: quais grupos criptográficos o cliente já envia prontos no primeiro voo e em que ordem — por exemplo, suporte pós-quântico híbrido **`X25519MLKEM768` (`0x11ec`)** seguido de `X25519` (`0x001d`) nos browsers modernos vs. apenas `X25519` + `P-256` em stacks padrão.
    - **`compress_certificate` (`0x001b`, [RFC 8879](https://www.rfc-editor.org/rfc/rfc8879))**: algoritmos aceitos e ordem (`brotli`=2 no Chrome, `zlib`=1 em stacks Apple/Safari, `zstd`=3, ou ausência da extensão no `crypto/tls` default do Go).
    - **`application_settings` / `ALPS` (`0x4469` legado e `0x44cd` novo)**: extensão usada pelo Chromium para negociar parâmetros de HTTP/2 e HTTP/3 já dentro do handshake TLS.
    - **`delegated_credentials` (`0x0022`, [RFC 9345](https://www.rfc-editor.org/rfc/rfc9345))**: típica do Firefox.
    - **Record Layer e Session ID**: `legacy_record_version` do primeiro registro (`0x0301` vs `0x0303`), fragmentação proposital do `ClientHello` em múltiplos records TLS, e `legacy_session_id` (32 bytes aleatórios no modo de compatibilidade de middlebox do TLS 1.3 sobre TCP, mas **obrigatoriamente vazio — 0 bytes — no QUIC** conforme [RFC 9001 §8.4](https://www.rfc-editor.org/rfc/rfc9001#section-8.4)).
- **ECH — Encrypted ClientHello ([RFC 9849](https://www.rfc-editor.org/rfc/rfc9849)) e `JA4E`**:
  - Quando o cliente usa ECH, o SNI real, o ALPN real e parte das extensões vão cifrados dentro do `Inner ClientHello`. Um proxy que **não** possui a chave privada ECH vê apenas o *Outer ClientHello* (SNI de cobertura como `cloudflare-ech.com` + extensão `0xfe0d` com suíte HPKE KEM/KDF/AEAD, `config_id` e tamanho do payload). Um proxy que **termina** ECH decifra o *Inner ClientHello* e pode calcular o `JA4` real do cliente além de validar a consistência *Outer vs Inner*.
- **mTLS e Certificados (`JA4X` e Pinning / [RFC 9440](https://www.rfc-editor.org/rfc/rfc9440))**:
  - **Thumbprint / SPKI Pin**: hash criptográfico SHA-256 do certificado exato (DER) ou de sua chave pública (`SubjectPublicKeyInfo`), frequentemente repassado pelo proxy aos backends via header `Client-Cert` ([RFC 9440](https://www.rfc-editor.org/rfc/rfc9440)).
  - **`JA4X`**: hasheia os **OIDs em ordem** de `Issuer RDN` + `Subject RDN` + `X.509v3 Extensions` (sem os valores). Identifica a **ferramenta/autoridade geradora** do certificado (OpenSSL default, Go `crypto/x509`, `mkcert`, Let's Encrypt, corporativo, ou frameworks de C2) mesmo quando o certificado e a chave mudam a cada conexão.
- **Fingerprinting de Servidores Upstream (`JA3S`, `JA4S` e `JARM`)**:
  - Num reverse proxy ou forward proxy que abre conexões TLS/QUIC para backends ou destinos externos:
    - **`JA3S` / `JA4S` (passivo)**: resume o `ServerHello` respondido pelo servidor de destino (versão escolhida, cipher suite selecionado e lista ordenada de extensões retornadas). Detecta interceptação MITM ou mudanças inesperadas na stack do backend.
    - **`JARM` (ativo)**: envia 10 conexões TLS com `ClientHello`s variados (versões, ordens de ciphers, ALPNs) e combina os 10 `ServerHello`s num hash fuzzy de 62 caracteres — usado tanto por scanners externos para descobrir que um IP roda **Traefik / Go `crypto/tls`** quanto por proxies de segurança para auditar origens.

---

### 4. Camada HTTP — Todas as Versões (`HTTP/0.9`, `HTTP/1.0`, `HTTP/1.1`, `HTTP/2`, `HTTP/3`)

#### 4.1 `HTTP/0.9` (One-line protocol)
- Formato histórico pré-headers: apenas `GET /caminho\r\n` (ou `\n` puro), sem string `HTTP/...`, sem cabeçalhos e com encerramento da conexão logo após a resposta.
- Proxies modernos normalmente rejeitam ou bloqueiam `HTTP/0.9`, mas observar requisições de linha única na porta TCP (terminador `CRLF` vs `LF`, bytes extras após o path, ausência de `Host`) identifica instantaneamente scanners manuais (`nc`), IoT embarcado rudimentar e sondas de vulnerabilidade.

#### 4.2 `HTTP/1.0` ([RFC 1945](https://www.rfc-editor.org/rfc/rfc1945)) e `HTTP/1.1` ([RFC 9112](https://www.rfc-editor.org/rfc/rfc9112))
Por serem protocolos textuais na rede, `HTTP/1.0` e `HTTP/1.1` expõem variações sintáticas que **desaparecem completamente** no `HTTP/2` e no `HTTP/3` (onde cabeçalhos são binários e obrigatoriamente minúsculos):

- **`JA4H` (`a_b_c_d`)**: aplicável a qualquer versão HTTP (`10`, `11`, `20`, `30`), composto por:
  - `a`: 2 letras do método (`ge`, `po`, `pu`...) + versão (`10`, `11`, `20`, `30`) + presença de `Cookie` (`c`/`n`) + presença de `Referer` (`r`/`n`) + contagem de headers (2 dígitos, ignorando `Cookie` e `Referer`) + 4 caracteres do idioma primário em `Accept-Language` (`ptbr`, `enus`, `0000`).
  - `b`: 12 hex do SHA-256 dos **nomes dos headers na ordem exata recebida** (excluindo `Cookie` e `Referer`).
  - `c`: 12 hex do SHA-256 dos **nomes dos cookies ordenados** (`000000000000` se sem cookies).
  - `d`: 12 hex do SHA-256 de `nome=valor` dos **cookies ordenados** (permite rastrear a mesma sessão de cliente mesmo que mude de IP/rede, sem logar os cookies em claro).
- **Sinais exclusivos da serialização textual `HTTP/1.0` / `HTTP/1.1`**:
  - **Casing exato dos nomes de headers**: `User-Agent` vs `user-agent`, `Sec-CH-UA` vs `sec-ch-ua`, `Content-Length` vs `content-length`, `TE` vs `Te`.
  - **Ordem em relação ao `Host` e ordenação alfabética**: browsers colocam `Host` sempre em primeiro lugar numa ordem fixa de engine; já o `net/http` do Go (`Request.Write`) emite `Host`, `User-Agent` e depois **ordena os demais headers em ordem lexicográfica**, criando uma assinatura inconfundível de cliente Go se o desenvolvedor não controlar o buffer bruto.
  - **Espaçamento e quebras de linha**: espaço opcional após `:` (`Header: valor` vs `Header:valor`), `CRLF` (`\r\n`) vs `LF` tolerado (`\n`), `origin-form` (`GET /path HTTP/1.1`) vs `absolute-form` (`GET http://host/path HTTP/1.1`, obrigatório para forward proxies mas anômalo em reverse proxies).
  - **Semântica de persistência e framing de corpo**: `Connection: keep-alive` explícito no `HTTP/1.0` vs implícito no `HTTP/1.1`, uso de *HTTP pipelining*, e formatação hexadecimal de tamanho de blocos em `Transfer-Encoding: chunked` (minúsculas `1f` vs maiúsculas `1F`, zeros à esquerda, presença de chunk extensions/trailers).

#### 4.3 `HTTP/2` (`h2` sobre TLS e `h2c` em claro — [RFC 9113](https://www.rfc-editor.org/rfc/rfc9113))
O protocolo binário de frames introduz o **Akamai HTTP/2 Fingerprint**, padronizado informalmente como `S[id:val;...]|WU|P[stream:excl:dep:weight,...]|m,a,s,p`:

1. **Frame `SETTINGS` inicial (IDs, ordem exata e valores)**:
   - `1` `HEADER_TABLE_SIZE`, `2` `ENABLE_PUSH` (`0` nos browsers modernos; `1` ou omitido em libs antigas), `3` `MAX_CONCURRENT_STREAMS`, `4` `INITIAL_WINDOW_SIZE` (ex.: Chromium `6291456`, Firefox `131072`, Safari/WebKit `2097152`/`4194304`, Go `x/net/http2` `4194304`), `5` `MAX_FRAME_SIZE`, `6` `MAX_HEADER_LIST_SIZE`, `8` `ENABLE_CONNECT_PROTOCOL` ([RFC 8441](https://www.rfc-editor.org/rfc/rfc8441)), `9` `NO_RFC7540_PRIORITIES` ([RFC 9218](https://www.rfc-editor.org/rfc/rfc9218)) e settings GREASE.
2. **`WINDOW_UPDATE` de conexão (`stream_id = 0`)**:
   - Incremento enviado imediatamente após o `SETTINGS` (ex.: Chromium `15663105`, Firefox `12517377`, Go `x/net/http2` `1073741824`, ou `00` quando não enviado no primeiro voo).
3. **Priorização de Streams (`PRIORITY` legado vs `PRIORITY_UPDATE` [RFC 9218](https://www.rfc-editor.org/rfc/rfc9218))**:
   - Árvores de streams fantasma da [RFC 7540](https://www.rfc-editor.org/rfc/rfc7540) vs migração moderna para o header `Priority` (`u=0, i`) e frames `PRIORITY_UPDATE` (`0x10`).
4. **Ordem exata dos Pseudo-Headers**:
   - **Chromium / Chrome / Edge**: `:method, :authority, :scheme, :path` (`m,a,s,p`)
   - **Firefox**: `:method, :path, :authority, :scheme` (`m,p,a,s`)
   - **Safari / Apple CFNetwork**: `:method, :scheme, :path, :authority` (`m,s,p,a`) ou `m,s,a,p` conforme versão do iOS/macOS
   - Clientes como `curl`/`nghttp2` e Go `x/net/http2` possuem ordens fixas próprias.
5. **Detalhes adicionais de HPACK ([RFC 7541](https://www.rfc-editor.org/rfc/rfc7541)) e framing**:
   - Decisão de indexar na tabela dinâmica vs *Literal Without Indexing* vs *Never Indexed* (para `cookie` e `authorization`), ativação do bit de codificação **Huffman** em strings curtas, empacotamento do preface + `SETTINGS` + `WINDOW_UPDATE` + `HEADERS` num único record TLS vs múltiplos records, e em **`h2c`** o formato do upgrade (`HTTP2-Settings` vs *Prior Knowledge*).

#### 4.4 `HTTP/3` (`h3` sobre QUIC — [RFC 9114](https://www.rfc-editor.org/rfc/rfc9114) & QPACK [RFC 9204](https://www.rfc-editor.org/rfc/rfc9204))
No `HTTP/3`, o controle de fluxo (`WINDOW_UPDATE`) desceu para os **QUIC Transport Parameters**, mas a camada de aplicação HTTP/3 mantém um conjunto próprio e rico de fingerprints (sempre combinado ao fingerprint QUIC subjacente):

1. **Sequência e tipos de Unidirectional Streams abertas pelo cliente**:
   - Ordem e timing de abertura da *Control Stream* (`0x00`), *QPACK Encoder Stream* (`0x02`), *QPACK Decoder Stream* (`0x03`) e **Unidirectional Streams GREASE** (`0x1f * N + 0x21`). Muitas bibliotecas HTTP/3 de automação abrem apenas a `Control Stream` (ou não abrem streams GREASE), diferenciando-se imediatamente de Chrome/Firefox/Safari.
2. **Frame `SETTINGS` do HTTP/3 (primeiro frame da Control Stream `0x00` — ordem e valores)**:
   - `0x01` `SETTINGS_QPACK_MAX_TABLE_CAPACITY` (ex.: `0` quando a lib desativa QPACK dinâmico — caso default de várias libs como `quic-go/http3` — vs `16384` ou `65536` nos browsers).
   - `0x06` `SETTINGS_MAX_FIELD_SECTION_SIZE` (limite de headers).
   - `0x07` `SETTINGS_QPACK_BLOCKED_STREAMS` (ex.: `0` vs `100`).
   - `0x08` `SETTINGS_ENABLE_CONNECT_PROTOCOL` ([RFC 9220](https://www.rfc-editor.org/rfc/rfc9220) — WebSockets/WebTransport sobre H3).
   - `0x33` `SETTINGS_H3_DATAGRAM` ([RFC 9297](https://www.rfc-editor.org/rfc/rfc9297)) e settings de `WebTransport`.
   - **Settings IDs GREASE e Frames GREASE** (`0x1f * N + 0x21`) injetados nas streams de controle e de requisição.
3. **Comportamento QPACK ([RFC 9204](https://www.rfc-editor.org/rfc/rfc9204))**:
   - Uso efetivo de inserções dinâmicas na *Encoder Stream* e streams bloqueadas vs codificação puramente estática/literal, uso de Huffman e flag *Never Indexed*.
4. **Pseudo-Headers, Headers regulares (`JA4H` com versão `30`) e Prioridades ([RFC 9218](https://www.rfc-editor.org/rfc/rfc9218))**:
   - Mesma distinção de ordem de `:method`, `:authority`, `:scheme`, `:path` (e `:protocol`) vista no HTTP/2, somada ao header `Priority` e aos frames `PRIORITY_UPDATE` (`0x0f0700`) na Control Stream.

---

### 5. Túneis, Upgrades e Semântica Específica de Servidores Proxy

Um servidor proxy vê superfícies adicionais que servidores de aplicação comuns não enxergam:

- **Forward Proxy & Tunneling (`CONNECT`, `CONNECT-UDP` / `MASQUE`, `CONNECT-IP`)**:
  - **`HTTP/1.1 CONNECT host:port HTTP/1.1`**: conjunto, casing e ordem dos headers enviados ao proxy *antes* do túnel TLS iniciar (`Host`, `User-Agent`, `Proxy-Authorization` e o header legado não padronizado `Proxy-Connection: keep-alive`, que browsers e ferramentas tratam de formas distintas).
  - **Extended `CONNECT` em HTTP/2 ([RFC 8441](https://www.rfc-editor.org/rfc/rfc8441)) e HTTP/3 ([RFC 9220](https://www.rfc-editor.org/rfc/rfc9220))**: presença e posição do pseudo-header `:protocol` (`websocket`, `webtransport`, `connect-udp`, `connect-ip`).
  - **`MASQUE` ([RFC 9298](https://www.rfc-editor.org/rfc/rfc9298) `CONNECT-UDP` / [RFC 9484](https://www.rfc-editor.org/rfc/rfc9484) `CONNECT-IP`)**: uso do header `Capsule-Protocol: ?1` e encapsulamento de `HTTP Datagrams` sobre HTTP/3 (usado por Apple iCloud Private Relay, Cloudflare WARP e Chrome IP Protection).
- **WebSocket ([RFC 6455](https://www.rfc-editor.org/rfc/rfc6455)) e gRPC**:
  - **WebSocket**: parâmetros e ordem em `Sec-WebSocket-Extensions` (`permessage-deflate; client_max_window_bits`), entropia da `masking-key` de 4 bytes por frame, fragmentação e cadência de `Ping`/`Pong`.
  - **gRPC (sobre H2/H3)**: `te: trailers`, `grpc-accept-encoding`, `user-agent` estruturado (`grpc-go/...`, `grpc-java/...`), tamanho de janela inicial H2 e cadência de `PING` keepalive.
- **Headers Semânticos, `Alt-Svc` e Cadeia de Proxies**:
  - **Client Hints & Fetch Metadata**: coerência entre `User-Agent`, `Sec-CH-UA*`, `Sec-Fetch-*`, `Accept` e `Accept-Encoding` (ex.: suporte e posição de **`zstd`** em `gzip, deflate, br, zstd`).
  - **Transição `Alt-Svc` ([RFC 7838](https://www.rfc-editor.org/rfc/rfc7838))**: um browser real normalmente conecta primeiro em TCP (`JA4` `t13...` + HTTP/2), recebe `Alt-Svc: h3=":443"` do proxy e migra as requisições seguintes para QUIC (`JA4` `q13...` + HTTP/3) mantendo sessão/cookies coerentes. Bots costumam travar em TCP ignorando `Alt-Svc`, ou forçar H3 direto com parâmetros QUIC incompatíveis com o `User-Agent`.
  - **PROXY Protocol v1/v2 (HAProxy)**: quando o proxy HTTP/QUIC fica atrás de um balanceador L4, o IP real, opções TCP e até dados TLS originais podem chegar encapsulados em **TLVs do PROXY Protocol v2** (`PP2_TYPE_ALPN`, `PP2_TYPE_AUTHORITY`, `PP2_TYPE_SSL`, ou TLVs customizados com o `JA4`/`JA4T` já calculado na borda L4).
  - **Padrão de Multiplexação e Coalescência de Conexão**: dezenas de usuários distintos compartilhando uma única conexão HTTP/2 ou HTTP/3 apontam um proxy/gateway intermediário agregando tráfego; no extremo oposto, abrir uma nova conexão TCP+TLS para cada sub-recurso sem reutilizar streams H2/H3 denuncia scrapers rotacionando proxies por request.

---

## Exemplos de strings reais

**JA3** (MD5 de `771,4865-4866-4867-49195-49199...,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0`):

```text
cd08e31494f9531f560d64c695473da9
```

**JA4 sobre TCP (`t` + TLS 1.3 + SNI + 15 ciphers + 16 extensões + `h2`) vs. JA4 sobre QUIC (`q` + `h3`)**:

```text
t13d1516h2_8daaf6152771_02713d6af862
q13d0312h3_55b375c5d22e_cd85d2d88918
```

**JA4H (`GET`, `HTTP/2`, com `Cookie` e `Referer`, 14 headers, `pt-BR`)**:

```text
ge20cr14ptbr_e0632c96295c_7590292b285c_9c9222d54328
```

**JA4T (TCP `SYN`: Window `65535`, Options `MSS-NOP-WScale-NOP-NOP-TS-SACK-EOL`, MSS `1460`, WScale `8`)**:

```text
65535_2-1-3-1-1-8-4-0_1460_8
```

**Akamai HTTP/2 Fingerprint (Chromium típico)**:

```text
1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p
```

---

## Links oficiais e especificações de referência

- **JA3 / JA3S / CYU (Salesforce)**: <https://github.com/salesforce/ja3> · <https://github.com/salesforce/cyu> · <https://engineering.salesforce.com/tls-fingerprinting-with-ja3-and-ja3s-247362855967/>
- **JARM (Active TLS Server Fingerprinting — Salesforce)**: <https://github.com/salesforce/jarm>
- **JA4+ (FoxIO — `JA4`, `JA4S`, `JA4H`, `JA4L`, `JA4X`, `JA4T`, `JA4TS`, `JA4D`, `JA4SSH`)**: <https://github.com/FoxIO-LLC/ja4> · <https://blog.foxio.io/ja4-network-fingerprinting> *(atenção: `JA4` é BSD-3-Clause, enquanto sub-especificações adicionais do JA4+ possuem licença própria da FoxIO — verifique o `LICENSE` do repositório antes de uso comercial)*
- **HTTP/2 Passive Fingerprinting (Akamai Whitepaper, Black Hat EU 2017)**: <https://www.blackhat.com/docs/eu-17/materials/eu-17-Shuster-Passive-Fingerprinting-Of-HTTP2-Clients-wp.pdf>
- **TCP/IP Passive OS Fingerprinting (`p0f` v3)**: <https://lcamtuf.coredump.cx/p0f3/>
- **RFCs essenciais da IETF**:
  - **GREASE (TLS)**: <https://www.rfc-editor.org/rfc/rfc8701> · **GREASE QUIC Bit**: <https://www.rfc-editor.org/rfc/rfc9287>
  - **TLS 1.3**: <https://www.rfc-editor.org/rfc/rfc8446> · **Cert Compression**: <https://www.rfc-editor.org/rfc/rfc8879> · **ECH**: <https://www.rfc-editor.org/rfc/rfc9849> · **Header `Client-Cert` (mTLS em proxies)**: <https://www.rfc-editor.org/rfc/rfc9440>
  - **QUIC v1 & QUIC-TLS**: <https://www.rfc-editor.org/rfc/rfc9000> · <https://www.rfc-editor.org/rfc/rfc9001> · **QUIC v2**: <https://www.rfc-editor.org/rfc/rfc9369> · **QUIC Datagrams**: <https://www.rfc-editor.org/rfc/rfc9221>
  - **HTTP/1.1**: <https://www.rfc-editor.org/rfc/rfc9112> · **HTTP/2 & HPACK**: <https://www.rfc-editor.org/rfc/rfc9113> · <https://www.rfc-editor.org/rfc/rfc7541> · **HTTP/3 & QPACK**: <https://www.rfc-editor.org/rfc/rfc9114> · <https://www.rfc-editor.org/rfc/rfc9204> · **Extensible Priorities**: <https://www.rfc-editor.org/rfc/rfc9218>
  - **MASQUE (`CONNECT-UDP` / `CONNECT-IP`)**: <https://www.rfc-editor.org/rfc/rfc9298> · <https://www.rfc-editor.org/rfc/rfc9484>
- **Ferramentas para emulação e validação contra browsers reais**:
  - Emulação TLS/H2/H3: <https://github.com/lwthiker/curl-impersonate> · <https://github.com/refraction-networking/utls>
  - Endpoints públicos de inspeção: <https://tls.peet.ws/api/all> · <https://tls.browserleaks.com/json> · <https://quic.browserleaks.com/>

---

## Aplicado a este repositório (Traefik)

Analisando a arquitetura atual do Traefik (Go `1.27` em `go.mod`, `crypto/tls`, `net/http`, `golang.org/x/net/http2` e `github.com/quic-go/quic-go`), a viabilidade de captura muda bastante conforme a camada:

1. **`JA4` (`t` em TCP e `q` em QUIC) — já viável direto via `crypto/tls.ClientHelloInfo`**:
   - Desde o Go 1.24 (e presente no Go deste repositório), `tls.ClientHelloInfo` passou a expor **`Extensions []uint16`**, além de `CipherSuites`, `SignatureSchemes`, `SupportedCurves`, `SupportedPoints`, `SupportedProtos` e `SupportedVersions` **na ordem bruta da rede e preservando valores GREASE**.
   - Como `GetConfigForClient` é invocado tanto para HTTPS/TCP (`pkg/server/server_entrypoint_tcp.go`) quanto pelo `quic-go` para HTTP/3 (`pkg/server/server_entrypoint_tcp_http3.go`), é possível calcular o **`JA4` completo (`t...` e `q...`)** sem parsear pacotes manualmente.
2. **`JA3` estrito, Deep TLS Extensions e QUIC Transport Parameters (`0x0039`)**:
   - `tls.ClientHelloInfo` não expõe o campo `legacy_version` bruto do cabeçalho (exigido pelo `JA3`), o `legacy_record_version`, o tamanho de `padding` nem os *bytes internos* de extensões opacas (`compress_certificate`, `ALPS`, `key_share` ou `quic_transport_parameters`).
   - **Em TCP**: o Traefik já intercepta o início da conexão sem consumir bytes via `peekConn` em `pkg/server/router/tcp/router.go` (`clientHelloInfo`); ler o record TLS `0x16` ali entrega todos os bytes brutos do `ClientHello`.
   - **Em QUIC (`quic-go`)**: o `ClientHello` viaja dentro de frames `CRYPTO` de pacotes UDP `Initial`. Para extrair **QUIC Transport Parameters**, tamanho do datagrama `Initial` e frames QUIC/H3, o caminho limpo é acoplar um `Tracer` (`qlog`) em `quic.Config` no `http3server` (`pkg/server/server_entrypoint_tcp_http3.go`, onde hoje `QUICConfig` define apenas `Allow0RTT: false`) ou envolver o `net.PacketConn` para decodificar o pacote `Initial`.
3. **HTTP/1.0 e HTTP/1.1 (`JA4H`, ordem e casing de headers)**:
   - O `net/http` converte os cabeçalhos para `http.Header` (`map[string][]string`) e aplica `CanonicalMIMEHeaderKey`, perdendo **ordem** e **casing** antes de qualquer middleware HTTP ou plugin Yaegi/WASM rodar. Capturar `JA4H` e anomalias sintáticas de H1.x exige inspecionar os bytes do cabeçalho HTTP no wrapper de `net.Conn` do EntryPoint antes do `http.Server` (armazenando no `ConnContext`).
4. **HTTP/2 (Akamai H2 Fingerprint) e HTTP/3 (`SETTINGS` H3 / QPACK / Pseudo-Headers)**:
   - Tanto `golang.org/x/net/http2` quanto `quic-go/http3` consomem internamente os frames `SETTINGS`, `WINDOW_UPDATE`, `PRIORITY`/`PRIORITY_UPDATE`, compressão HPACK/QPACK e os pseudo-headers (`:method`, `:authority`, `:scheme`, `:path`), entregando ao `http.Handler` apenas o `*http.Request` já normalizado. Expor o fingerprint H2/H3 requer interceptar os frames na conexão TLS desencapsulada (para H2) e hooks/tracing na `Control Stream` / `Request Stream` do `quic-go/http3` (para H3).
5. **mTLS (`JA4X` e Cert/SPKI Pinning) — disponível hoje em middlewares**:
   - `req.TLS.PeerCertificates` já disponibiliza os certificados X.509 completos (`cert.Raw` em DER) diretamente no `http.Request` tanto em HTTP/1.1 e HTTP/2 quanto em HTTP/3, permitindo calcular `JA4X` e SHA-256 SPKI/Cert num middleware comum (complementando o `passTLSClientCert` já existente em `pkg/middlewares/passtlsclientcert/`).
6. **TCP/IP (`JA4T` / `p0f`)**:
   - Um `net.Listener` padrão em Go não enxerga o pacote `SYN` do kernel. Capturá-lo exige opções de socket específicas do SO em `ListenConfig.Control` (como `TCP_SAVE_SYN` no Linux + `getsockopt` após o `Accept`), um programa `eBPF`/`XDP` auxiliar, ou receber os dados via TLVs do `go-proxyproto` quando um balanceador L4 está à frente do Traefik.
