/* Área de membros Sabonetes de Sucesso: fileiras, senha, leitor de PDF e aulas (sem framework) */
(() => {
  'use strict';
  const D = window.DADOS;
  if (!D) return;

  // Como pagar, mostrado na folha de liberar. Pra esconder a chave do site, troque por: const PAGAMENTO = null;
  const PAGAMENTO = { valor: '24,90', chave: '63877231000106', tipo: 'CNPJ', nota: 'No banco aparece o nome Luan Araujo, marido da Ana.' };

  const html = document.documentElement;
  const $ = (s, el = document) => el.querySelector(s);
  const $$ = (s, el = document) => Array.from(el.querySelectorAll(s));
  const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const ico = (nome, extra = '') => `<svg class="ico ${extra}" aria-hidden="true"><use href="#i-${nome}"></use></svg>`;
  const normal = (s) => String(s).normalize('NFD').replace(/[̀-ͯ]/g, '').toLowerCase().replace(/[^a-z0-9]/g, '');
  const deB64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
  const paraB64 = (buf) => { const b = new Uint8Array(buf); let s = ''; for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]); return btoa(s); };
  const quieto = () => matchMedia('(prefers-reduced-motion: reduce)').matches;
  const espera = (ms) => new Promise((r) => setTimeout(r, ms));
  const tempo = (min) => { if (min < 60) return `${min} min`; const h = Math.floor(min / 60), m = min % 60; return m ? `${h} h ${m} min` : `${h} h`; };
  const duracao = (seg) => tempo(Math.max(1, Math.round(seg / 60)));
  const fmtChave = (c, tipo) => (tipo === 'CNPJ' && c.length === 14 ? `${c.slice(0, 2)}.${c.slice(2, 5)}.${c.slice(5, 8)}/${c.slice(8, 12)}-${c.slice(12)}` : c);
  const thumb = (id) => `https://i.ytimg.com/vi/${encodeURIComponent(id)}/mqdefault.jpg`;

  // ---------- guardado no aparelho (tolerante a navegador que bloqueia) ----------
  const guarda = {
    ler(k, padrao) { try { const v = localStorage.getItem('sds.' + k); return v == null ? padrao : JSON.parse(v); } catch (e) { return padrao; } },
    gravar(k, v) { try { localStorage.setItem('sds.' + k, JSON.stringify(v)); } catch (e) { /* sem espaço ou bloqueado */ } },
    apagar(k) { try { localStorage.removeItem('sds.' + k); } catch (e) { /* idem */ } },
  };
  const prog = guarda.ler('progresso', {}); // { idDoVideo: { t: segundos, v: 1 = assistida, em: quando } }
  const lidas = guarda.ler('paginas', {}); // { idDoPdf: última página lida }
  const salvarProg = () => guarda.gravar('progresso', prog);
  let tLidas = 0;
  const salvarLidas = () => { clearTimeout(tLidas); tLidas = setTimeout(() => guarda.gravar('paginas', lidas), 400); };

  const estado = { liberado: html.hasAttribute('data-liberado'), chave: null, segredo: null, cofre: null };

  // ---------- cripto: PBKDF2-SHA256 -> AES-GCM, arquivo = iv(12) + cifra ----------
  async function derivarChave(senhaNormal) {
    const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(senhaNormal), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt: deB64(D.kdf.salt), iterations: D.kdf.iter, hash: 'SHA-256' },
      base, { name: 'AES-GCM', length: 256 }, true, ['decrypt']);
  }
  const decifrar = (buf, chave) => { const b = new Uint8Array(buf); return crypto.subtle.decrypt({ name: 'AES-GCM', iv: b.slice(0, 12) }, chave, b.slice(12)); };
  async function baixar(url, aoAvancar) {
    const r = await fetch(url);
    if (!r.ok) throw new Error('http ' + r.status);
    const total = Number(r.headers.get('content-length')) || 0;
    if (!aoAvancar || !total || !r.body || !r.body.getReader) return r.arrayBuffer();
    const leitor = r.body.getReader();
    const partes = [];
    let recebido = 0;
    for (;;) {
      const { done, value } = await leitor.read();
      if (done) break;
      partes.push(value);
      recebido += value.length;
      aoAvancar(Math.min(1, recebido / total));
    }
    const tudo = new Uint8Array(recebido);
    let pos = 0;
    for (const p of partes) { tudo.set(p, pos); pos += p.length; }
    return tudo.buffer;
  }
  async function abrirCofre(chave) {
    if (!estado.cofre) estado.cofre = await baixar(D.cofre);
    const plano = await decifrar(estado.cofre, chave);
    return JSON.parse(new TextDecoder().decode(plano));
  }
  async function guardarChave(chave) {
    const bruta = await crypto.subtle.exportKey('raw', chave);
    guarda.gravar('chave', { k: paraB64(bruta), s: D.kdf.salt });
  }
  // o GitHub Pages deixa o navegador guardar o js/dados.js por até 10 min: se a senha ou o conteúdo mudou nesse
  // meio tempo, a página aberta aponta pra um cofre que já não existe. Antes de abrir o cofre, confere a versão
  // atual (js/dados.json, sem cache) e passa a usar o sal e o cofre novos. Sem internet, segue com o que tem.
  async function dadosAtuais() {
    try {
      const r = await fetch('js/dados.json', { cache: 'no-store' });
      if (!r.ok) return;
      const novo = await r.json();
      if (novo.versao && novo.versao !== D.versao) {
        D.versao = novo.versao; D.kdf = novo.kdf; D.cofre = novo.cofre;
        estado.cofre = null;
      }
    } catch (e) { /* sem internet */ }
  }
  async function chaveGuardada() {
    const g = guarda.ler('chave', null);
    if (!g || g.s !== D.kdf.salt) return null;
    try { return await crypto.subtle.importKey('raw', deB64(g.k), 'AES-GCM', false, ['decrypt']); } catch (e) { return null; }
  }
  async function garantirSegredo() {
    if (estado.segredo) return estado.segredo;
    await dadosAtuais();
    if (!estado.chave) estado.chave = await chaveGuardada();
    if (!estado.chave) throw new Error('sem chave');
    estado.segredo = await abrirCofre(estado.chave);
    renderTudo();
    return estado.segredo;
  }

  // ---------- aulas (só depois da senha) ----------
  const aulasDo = (mid) => estado.segredo?.modulos?.[mid]?.aulas || [];
  const vistas = (mid) => aulasDo(mid).filter((a) => prog[a.id]?.v).length;
  function acharAula(vid) {
    for (const m of D.modulos) {
      const lista = aulasDo(m.id);
      const i = lista.findIndex((a) => a.id === vid);
      if (i >= 0) return { m, i, a: lista[i] };
    }
    return null;
  }
  function proxima(loc) {
    const lista = aulasDo(loc.m.id);
    if (loc.i + 1 < lista.length) return { m: loc.m, i: loc.i + 1, a: lista[loc.i + 1] };
    for (let k = D.modulos.indexOf(loc.m) + 1; k < D.modulos.length; k++) {
      const l = aulasDo(D.modulos[k].id);
      if (l.length) return { m: D.modulos[k], i: 0, a: l[0] };
    }
    return null;
  }
  function retomar(mid) {
    const lista = aulasDo(mid);
    let melhor = -1, em = 0;
    lista.forEach((a, i) => { const p = prog[a.id]; if (p && !p.v && (p.em || 0) > em) { em = p.em; melhor = i; } });
    if (melhor >= 0) return melhor;
    const i = lista.findIndex((a) => !prog[a.id]?.v);
    return i >= 0 ? i : 0;
  }
  function continuar() {
    if (!estado.segredo) return [];
    const itens = [];
    const usadas = new Set();
    const ordem = Object.entries(prog).filter(([, p]) => p.em).sort((x, y) => y[1].em - x[1].em);
    for (const [vid, p] of ordem) {
      let loc = acharAula(vid);
      if (loc && p.v) loc = proxima(loc);
      if (!loc || prog[loc.a.id]?.v || usadas.has(loc.a.id)) continue;
      usadas.add(loc.a.id);
      itens.push(loc);
      if (itens.length === 8) break;
    }
    return itens;
  }
  const pct = (a) => { const p = prog[a.id]; if (p?.v) return 100; return p?.t && a.d ? Math.min(99, Math.round((p.t / a.d) * 100)) : 0; };

  // ---------- fileiras ----------
  // cadeado de cartão paisagem (capa do módulo, aula): canto de cima; some quando o cartão perde o data-bloqueado
  const cadeado = (extra = '') => `<span class="cadeado ${extra}" aria-hidden="true">${ico('lock-simple-fill', 'fechado')}${ico('lock-simple-open', 'aberto')}</span>`;
  // pôster bloqueado: o cadeado vai junto do aviso, embaixo, pra não cobrir o título da capa
  const avisoPix = () => `<span class="rotulo-bloqueio" aria-hidden="true">${ico('lock-simple-fill')}<span>Liberado após&nbsp;o&nbsp;Pix</span></span>`;
  // linha de informações que só quebra depois de um ponto
  const linhaMeta = (partes) => partes.filter(Boolean).map((p) => esc(p).replace(/ /g, '&nbsp;')).join('&nbsp;<span class="ponto" aria-hidden="true">·</span> ');
  const previa = (m, i) => `img/previas/${m.id}-${String(i + 1).padStart(2, '0')}.webp`;
  const thumbGrande = (id) => `https://i.ytimg.com/vi/${encodeURIComponent(id)}/hqdefault.jpg`;
  // as aulas bloqueadas vão ficando mais transparentes pra direita (a curva fica no CSS, pelo --i: mais forte no celular)
  const opacidade = (i) => String(i);

  function poster({ id, titulo, meta, capa, bloqueado, p = 0, rotulo }) {
    return `<button class="cartao cartao-poster" id="c-pdf-${esc(id)}" type="button" data-tipo="pdf" data-id="${esc(id)}"${bloqueado ? ' data-bloqueado' : ''} aria-label="${esc(rotulo)}">
      <span class="cartao-arte"><img src="${esc(capa)}" alt="" width="420" height="630" loading="lazy" decoding="async">${bloqueado ? avisoPix() : ''}${p ? `<span class="progresso"><i style="--p:${p}%"></i></span>` : ''}</span>
      <span class="cartao-titulo">${esc(titulo)}</span>
      <span class="cartao-meta">${esc(meta)}</span>
    </button>`;
  }
  function renderGratis() {
    $('#trilho-gratis').innerHTML = D.gratis.map((g) => {
      const n = lidas[g.id];
      const meta = n > 1 ? `Página ${n} de ${g.paginas}` : `${g.paginas} páginas`;
      return poster({ id: g.id, titulo: g.titulo, meta, capa: g.capa, p: n > 1 ? Math.max(2, Math.round((n / g.paginas) * 100)) : 0, rotulo: `Ler ${g.titulo}, ${meta}` });
    }).join('');
  }
  function renderBonus() {
    const bloq = !estado.liberado;
    $('#trilho-bonus').innerHTML = D.bonus.map((b) => {
      const n = lidas[b.id];
      const meta = !bloq && n > 1 ? `Página ${n} de ${b.paginas}` : `${b.paginas} páginas`;
      return poster({ id: b.id, titulo: b.titulo, meta, capa: b.capa, bloqueado: bloq,
        p: !bloq && n > 1 ? Math.max(2, Math.round((n / b.paginas) * 100)) : 0,
        rotulo: bloq ? `Bônus ${b.titulo}, ${b.paginas} páginas, liberado após o Pix` : `Ler o bônus ${b.titulo}, ${meta}` });
    }).join('');
  }

  // uma fileira por módulo, como os gêneros da Netflix: a capa do módulo primeiro e as aulas dele à direita
  function montarModulos() {
    $('#modulos').innerHTML = D.modulos.map((m) => `<section class="fileira fileira-modulo" id="mod-${m.id}" aria-labelledby="t-${m.id}">
        <div class="fileira-topo"><h2 id="t-${m.id}">${esc(m.titulo)}</h2><p class="fileira-info" id="info-${m.id}"></p></div>
        <div class="trilho-caixa"><div class="trilho trilho-modulo" id="trilho-${m.id}"></div></div>
      </section>`).join('');
  }
  // travada = como aparece agora (na animação da senha ainda aparece travada); lib = o estado real, pro leitor de tela
  function cartaoCapa(m, travada, vis, lib) {
    const p = vis ? Math.round((vis / m.aulas) * 100) : 0;
    const rotulo = `${m.rotulo}: ${m.titulo}, ${m.aulas} aulas${!lib ? ', liberado após o Pix' : (vis ? `, ${vis} assistidas` : '')}. Abrir o módulo`;
    return `<button class="cartao cartao-capa" id="c-mod-${m.id}" type="button" data-tipo="modulo" data-id="${m.id}"${travada ? ' data-bloqueado' : ''} aria-label="${esc(rotulo)}">
      <span class="cartao-arte"><img src="${esc(m.img)}" alt="" width="720" height="402" loading="lazy" decoding="async"><span class="capa-titulo" aria-hidden="true">${esc(m.rotulo)}</span>${cadeado()}${p ? `<span class="progresso"><i style="--p:${p}%"></i></span>` : ''}</span>
    </button>`;
  }
  function cartaoAula(m, i, a, lib, revelar) {
    const d = (a && a.d) || (m.duracoes && m.duracoes[i]) || 0;
    const dur = d ? duracao(d) : '';
    if (!a) {
      // antes da senha (ou enquanto o cofre chega): a prévia borrada, sem título
      const travada = !lib;
      return `<button class="cartao cartao-aula" id="c-aula-${m.id}-${i}" type="button" data-tipo="aula" data-mod="${m.id}" data-i="${i}"${travada ? ` data-bloqueado style="--i:${opacidade(i)}"` : ''} aria-label="${esc(`Aula ${i + 1} de ${m.titulo}${dur ? `, ${dur}` : ''}${travada ? ', liberada após o Pix' : ''}`)}">
        <span class="cartao-arte"><img src="${previa(m, i)}" alt="" width="320" height="180" loading="lazy" decoding="async">${dur ? `<span class="aula-dur">${dur}</span>` : ''}${cadeado('cadeado-mini')}</span>
        <span class="cartao-titulo">Aula ${i + 1}</span>
      </button>`;
    }
    const p = pct(a);
    const vista = !!prog[a.id]?.v;
    return `<button class="cartao cartao-aula" id="c-aula-${m.id}-${i}" type="button" data-tipo="aula" data-mod="${m.id}" data-i="${i}"${revelar ? ` data-bloqueado style="--i:${opacidade(i)}"` : ''} aria-label="${esc(`Aula ${i + 1}: ${a.t}${dur ? `, ${dur}` : ''}${vista ? ', assistida' : ''}`)}">
      <span class="cartao-arte"><img src="${thumbGrande(a.id)}" alt="" width="480" height="270" loading="lazy" decoding="async">${revelar ? `<img class="previa" src="${previa(m, i)}" alt="" width="320" height="180" decoding="async">` : ''}${dur ? `<span class="aula-dur">${dur}</span>` : ''}${vista ? `<span class="aula-vista">${ico('check-circle-fill')}</span>` : ''}${revelar ? cadeado('cadeado-mini') : ''}${p ? `<span class="progresso"><i style="--p:${p}%"></i></span>` : ''}</span>
      <span class="cartao-titulo">${i + 1}. ${esc(a.t)}</span>
    </button>`;
  }
  // revelar = conteúdo liberado já na tela, ainda com cara de bloqueado, pra animação da senha
  function renderModulos(revelar = false) {
    const lib = estado.liberado;
    for (const m of D.modulos) {
      const lista = lib ? aulasDo(m.id) : [];
      const vis = lib ? vistas(m.id) : 0;
      $(`#info-${m.id}`).innerHTML = linhaMeta([vis ? `${vis} de ${m.aulas} aulas assistidas` : `${m.aulas} aulas`, tempo(m.minutos)]);
      let h = cartaoCapa(m, !lib || revelar, vis, lib);
      for (let i = 0; i < m.aulas; i++) h += cartaoAula(m, i, lista[i], lib, revelar);
      $(`#trilho-${m.id}`).innerHTML = h;
    }
  }
  function renderContinuar() {
    const itens = estado.liberado ? continuar() : [];
    $('#fileira-continuar').hidden = !itens.length;
    $('#trilho-continuar').innerHTML = itens.map(({ m, i, a }) => {
      const p = prog[a.id];
      const resta = p?.t ? Math.max(1, Math.round((a.d - p.t) / 60)) : 0;
      const meta = `${m.rotulo} · ${resta ? `faltam ${resta} min` : `aula ${i + 1}`}`;
      return `<button class="cartao cartao-paisagem" id="c-cont-${m.id}-${i}" type="button" data-tipo="aula" data-mod="${m.id}" data-vid="${esc(a.id)}" aria-label="${esc(`Continuar a aula ${a.t}, ${meta}`)}">
        <span class="cartao-arte"><img src="${thumbGrande(a.id)}" alt="" width="480" height="270" loading="lazy" decoding="async"><span class="tocar-icone" aria-hidden="true">${ico('play-fill')}</span><span class="progresso"><i style="--p:${Math.max(3, pct(a))}%"></i></span></span>
        <span class="cartao-titulo">${esc(a.t)}</span>
        <span class="cartao-meta">${esc(meta)}</span>
      </button>`;
    }).join('');
  }
  const botao = (tipo, icone, texto, acao) => `<button class="botao botao-${tipo}" type="button" data-acao="${acao}">${ico(icone)}<span>${esc(texto)}</span></button>`;
  function renderDestaque(animar) {
    const acoes = $('#destaque-acoes');
    const texto = $('#destaque-texto');
    $('#selo').setAttribute('aria-label', estado.liberado ? 'Tudo liberado. Ir para as aulas' : 'Liberar as aulas');
    if (estado.liberado) {
      const c = continuar()[0];
      // enquanto o cofre chega, quem já tem progresso vê "Continuar" (e não "Começar a primeira aula")
      const temProgresso = Object.values(prog).some((p) => p && p.em);
      if (c) texto.textContent = prog[c.a.id]?.t ? `Você parou em “${c.a.t}”.` : `Próxima aula: “${c.a.t}”.`;
      else texto.textContent = 'Tudo liberado pra você. Bom curso!';
      acoes.innerHTML = (c || (!estado.segredo && temProgresso)
        ? botao('principal', 'play-fill', 'Continuar assistindo', 'continuar')
        : botao('principal', 'play-fill', 'Começar a primeira aula', 'primeira'))
        + botao('secundario', 'list-bullets', 'Ver os módulos', 'modulos');
    } else {
      texto.textContent = 'Comece agora pelas 2 apostilas grátis. As aulas e os bônus são liberados depois do Pix.';
      acoes.innerHTML = botao('principal', 'book-open-text', 'Ler a apostila grátis', 'ler-gratis') + botao('secundario', 'lock-simple', 'Liberar as aulas', 'liberar');
    }
    if (animar && !quieto()) { acoes.classList.remove('trocando'); void acoes.offsetWidth; acoes.classList.add('trocando'); }
  }
  function renderTudo() {
    renderDestaque();
    renderContinuar();
    renderGratis();
    renderModulos();
    renderBonus();
    $$('.trilho-caixa').forEach((c) => c._setas?.());
  }

  // a assinatura: a página desliza até o 1º módulo e as aulas acendem uma por uma, da esquerda pra direita,
  // com os cadeados subindo; primeiro as que estão na tela, depois o resto
  // animar = false: sem animação (volta de quem já liberou, ou senha digitada de dentro de um módulo)
  function liberar(animar) {
    estado.liberado = true;
    html.setAttribute('data-liberado', '');
    if (!animar) { renderTudo(); return; }
    if (quieto()) {
      renderTudo();
      irPraAulas(true);
      aviso('Tudo liberado. Bom curso!');
      return;
    }
    const selo = $('#selo');
    selo.classList.remove('estalo'); void selo.offsetWidth; selo.classList.add('estalo');
    renderDestaque(true);
    renderContinuar();
    renderGratis();
    renderModulos(true);
    $$('.trilho-caixa').forEach((c) => c._setas?.());
    irPraAulas(false);
    const acender = (c) => {
      c.removeAttribute('data-bloqueado');
      c.style.removeProperty('--o');
      const r = c.getAttribute('aria-label');
      if (r) c.setAttribute('aria-label', r.replace(/, liberad[oa] após o Pix/, ''));
    };
    setTimeout(async () => {
      const todos = $$('.cartao[data-bloqueado]');
      const naTela = todos.filter((c) => { const r = c.getBoundingClientRect(); return r.bottom > 0 && r.top < innerHeight && r.right > 0 && r.left < innerWidth; });
      const resto = todos.filter((c) => !naTela.includes(c));
      // espera as miniaturas reais das aulas na tela (no máximo 1,5 s), pra elas acenderem já com a imagem
      await Promise.race([
        Promise.all(naTela.map((c) => { const im = $('.cartao-arte img:not(.previa)', c); return im && im.decode ? im.decode().catch(() => {}) : null; })),
        espera(1500),
      ]);
      const passo = Math.min(110, 1400 / Math.max(1, naTela.length));
      naTela.forEach((c, k) => setTimeout(() => acender(c), k * passo));
      const depois = naTela.length * passo + 250;
      resto.forEach((c, k) => setTimeout(() => acender(c), depois + k * 8));
      setTimeout(() => aviso('Tudo liberado. Bom curso!'), depois + resto.length * 8 + 500);
    }, 650);
  }
  // rola até a fileira do módulo 1 (abaixo do topo fixo) e leva o foco pro título dela
  function irPraAulas(instantaneo) {
    const id = D.modulos[0].id;
    $(`#mod-${id}`).scrollIntoView({ behavior: instantaneo || quieto() ? 'auto' : 'smooth', block: 'start' });
    const h = $(`#t-${id}`);
    if (h) { h.tabIndex = -1; h.focus({ preventScroll: true }); }
  }
  // ordem das fileiras (no HTML mesmo, pra ordem do Tab bater com a tela):
  // visitante = apostilas grátis, os 9 bônus logo em seguida (o que o Pix libera aparece cedo) e depois os módulos;
  // aluna que já liberou = continuar, módulos, apostilas, bônus
  function ordenarFileiras() {
    const f = $('#fileiras');
    const ordem = html.getAttribute('data-ordem') === 'aluna'
      ? ['#fileira-continuar', '#modulos', '#fileira-gratis', '#fileira-bonus', '#certificado']
      : ['#fileira-continuar', '#fileira-gratis', '#fileira-bonus', '#modulos', '#certificado'];
    ordem.forEach((s) => f.appendChild($(s)));
  }

  // ---------- camadas (folha, módulo, leitor) com o botão voltar do celular ----------
  const camadas = { liberar: $('#camada-liberar'), modulo: $('#camada-modulo'), leitor: $('#camada-leitor'), certificado: $('#camada-certificado'), oferta: $('#camada-oferta') };
  Object.values(camadas).forEach((c) => { const d = $('[role="dialog"]', c); if (d) d.tabIndex = -1; });
  const pilha = [];
  const aberta = (nome) => pilha.some((p) => p.nome === nome);
  // cada camada nova fica por cima da anterior (a folha de liberar aberta de dentro de um módulo aparece na frente)
  // e tudo que está por baixo fica inerte: o Tab e o leitor de tela não saem da camada de cima
  function atualizarInert() {
    const topo = pilha[pilha.length - 1];
    [$('#topo'), $('#conteudo'), $('.rodape'), $('.pular')].forEach((x) => { if (x) x.inert = Boolean(topo); });
    Object.values(camadas).forEach((c) => { c.inert = Boolean(topo) && c !== topo.el; });
  }
  function abrirCamada(nome, { aoFechar, foco } = {}) {
    const el = camadas[nome];
    const ativo = document.activeElement;
    const item = { nome, el, aoFechar, anterior: ativo, idAnterior: (ativo && ativo.id) || '' };
    el.hidden = false;
    el.style.zIndex = String(60 + pilha.length);
    void el.offsetWidth;
    el.classList.add('aberta');
    pilha.push(item);
    document.body.classList.add('travado');
    atualizarInert();
    history.pushState({ camada: nome }, '');
    const alvo = (foco && $(foco, el)) || $('[role="dialog"]', el);
    alvo?.focus({ preventScroll: true });
  }
  function fecharTopo() { if (pilha.length) history.back(); }
  function fecharItem(item) {
    item.el.classList.remove('aberta');
    item.aoFechar?.();
    setTimeout(() => { if (!item.el.classList.contains('aberta')) { item.el.hidden = true; item.el.style.zIndex = ''; } }, 360);
    if (!pilha.length) document.body.classList.remove('travado');
    atualizarInert();
    // o cartão que abriu pode ter sido redesenhado ao fechar: acha o equivalente pelo id e devolve o foco a ele
    const volta = (item.anterior && document.contains(item.anterior) && item.anterior)
      || (item.idAnterior && document.getElementById(item.idAnterior));
    if (volta) volta.focus({ preventScroll: true });
  }
  window.addEventListener('popstate', () => { const item = pilha.pop(); if (item) fecharItem(item); });
  document.addEventListener('keydown', (e) => {
    if (!pilha.length) return;
    if (e.key === 'Escape') {
      e.preventDefault();
      if (telaCheiaAgora()) { sairDaCheia(); return; } // primeiro sai da tela cheia, depois fecha a aula
      fecharTopo();
      return;
    }
    if (e.key !== 'Tab') return;
    const caixa = pilha[pilha.length - 1].el;
    const foc = $$('button:not([disabled]), a[href], input, [tabindex]:not([tabindex="-1"])', caixa).filter((x) => x.offsetParent !== null && !x.closest('[inert]'));
    if (!foc.length) return;
    const pri = foc[0], ult = foc[foc.length - 1];
    const i = foc.indexOf(document.activeElement);
    if (i === -1) { e.preventDefault(); (e.shiftKey ? ult : pri).focus(); return; }
    if (e.shiftKey && i === 0) { e.preventDefault(); ult.focus(); }
    else if (!e.shiftKey && i === foc.length - 1) { e.preventDefault(); pri.focus(); }
  });
  document.addEventListener('click', (e) => { if (e.target.closest('[data-fechar]')) fecharTopo(); });

  // ---------- folha de liberar ----------
  function abrirLiberar() {
    if (aberta('liberar')) return;
    const form = $('#senha-form');
    form.removeAttribute('data-erro');
    $('#senha-erro').textContent = '';
    const fino = matchMedia('(hover: hover) and (pointer: fine)').matches;
    abrirCamada('liberar', { foco: fino ? '#senha' : null });
  }
  function erroSenha(txt) {
    const form = $('#senha-form');
    form.setAttribute('data-erro', '');
    $('#senha-erro').textContent = txt;
    if (!quieto()) { form.classList.remove('tremendo'); void form.offsetWidth; form.classList.add('tremendo'); }
  }
  $('#senha-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const campo = $('#senha');
    const n = normal(campo.value);
    if (!n) { erroSenha('Digite a senha que a Ana te mandou no WhatsApp.'); campo.focus(); return; }
    const enviar = $('#senha-enviar');
    enviar.disabled = true;
    enviar.classList.add('carregando');
    $('#senha-erro').textContent = '';
    $('#senha-form').removeAttribute('data-erro');
    try {
      await dadosAtuais();
      const chave = await derivarChave(n);
      const segredo = await abrirCofre(chave);
      estado.chave = chave;
      estado.segredo = segredo;
      await guardarChave(chave);
      campo.value = '';
      campo.blur();
      // senha digitada de dentro de um módulo: o módulo vira liberado ali mesmo e as aulas dele entram uma a uma
      const noModulo = aberta('modulo') ? tocador.m : null;
      fecharTopo();
      await espera(quieto() ? 0 : 340);
      if (noModulo) {
        liberar(false);
        await abrirModulo(noModulo.id, { revelar: true });
        aviso('Tudo liberado. Bom curso!');
      } else {
        liberar(true);
      }
    } catch (err) {
      if (err && err.name === 'OperationError') erroSenha('Essa senha não confere. Confira na mensagem da Ana e digite de novo.');
      else erroSenha('Não consegui conferir agora. Veja se a internet está ligada e tente de novo.');
      campo.focus();
      campo.select();
    } finally {
      enviar.disabled = false;
      enviar.classList.remove('carregando');
    }
  });
  async function copiarPix() {
    if (!PAGAMENTO) return;
    try { await navigator.clipboard.writeText(PAGAMENTO.chave); } catch (e) {
      const t = document.createElement('textarea');
      t.value = PAGAMENTO.chave; t.setAttribute('readonly', ''); t.style.cssText = 'position:fixed;opacity:0;top:0';
      document.body.append(t); t.select();
      try { document.execCommand('copy'); } catch (e2) { /* sem cópia: a chave está escrita na tela */ }
      t.remove();
    }
    aviso('Chave Pix copiada');
  }

  // ---------- página do módulo e aulas ----------
  const tocador = { m: null, i: -1, yt: null, relogio: 0 };
  function paginaBloqueada(m) {
    const apostila = m.gratis ? D.gratis.find((g) => g.id === m.gratis) : null;
    // as aulas aparecem (prévia borrada, número e duração), mas trancadas: tocar numa leva pra folha de liberar
    const aulas = Array.from({ length: m.aulas }, (_, i) => {
      const d = m.duracoes && m.duracoes[i];
      const dur = d ? duracao(d) : '';
      return `<button class="aula aula-travada" type="button" data-acao="liberar" style="--o:${Math.max(0.4, 0.8 - i * 0.04).toFixed(2)}" aria-label="${esc(`Aula ${i + 1}${dur ? `, ${dur}` : ''}, liberada após o Pix`)}">
        <span class="aula-thumb"><img src="${previa(m, i)}" alt="" width="320" height="180" loading="lazy" decoding="async">${dur ? `<span class="aula-dur">${dur}</span>` : ''}${cadeado('cadeado-mini')}</span>
        <span class="aula-txt"><span class="aula-titulo">Aula ${i + 1}</span><span class="aula-meta">liberada após o Pix</span></span>
      </button>`;
    }).join('');
    return `<div class="pagina-capa">
        <img src="${esc(m.img)}" alt="" width="720" height="402">
        <span class="cadeado" aria-hidden="true">${ico('lock-simple-fill')}</span>
        <button class="fechar" type="button" data-fechar aria-label="Fechar">${ico('x')}</button>
      </div>
      <div class="pagina-corpo">
        <h2 class="pagina-titulo" id="modulo-titulo">${esc(m.titulo)}</h2>
        <p class="pagina-meta">${linhaMeta([m.rotulo, `${m.aulas} aulas`, tempo(m.minutos)])}</p>
        <p class="pagina-texto">As ${m.aulas} aulas deste módulo são liberadas depois do Pix, junto com todas as outras e os 9 bônus.</p>
        <div class="pagina-acoes">
          ${botao('principal', 'lock-simple', 'Liberar as aulas', 'liberar')}
          ${apostila ? `<button class="botao botao-secundario" type="button" data-acao="pdf" data-id="${esc(apostila.id)}">${ico('book-open-text')}<span>Ler a apostila grátis</span></button>` : ''}
        </div>
        <h3 class="temas-titulo">O que você aprende</h3>
        <ul class="temas">${m.temas.map((t) => `<li><span>${esc(t)}</span></li>`).join('')}</ul>
        <h3 class="temas-titulo">As ${m.aulas} aulas</h3>
        <div class="aulas">${aulas}</div>
      </div>`;
  }
  function linhaAula(a, i) {
    const p = pct(a);
    const vista = !!prog[a.id]?.v;
    return `<button class="aula" type="button" data-i="${i}" style="--i:${i}" aria-label="${esc(`Aula ${i + 1}: ${a.t}, ${duracao(a.d)}${vista ? ', assistida' : ''}`)}">
      <span class="aula-thumb"><img src="${thumb(a.id)}" alt="" width="320" height="180" loading="lazy" decoding="async"><span class="aula-dur">${duracao(a.d)}</span>${vista ? `<span class="aula-vista">${ico('check-circle-fill')}</span>` : ''}${p ? `<span class="progresso"><i style="--p:${p}%"></i></span>` : ''}</span>
      <span class="aula-txt"><span class="aula-titulo">${i + 1}. ${esc(a.t)}</span><span class="aula-meta">${duracao(a.d)}${vista ? ' · assistida' : ''}</span></span>
    </button>`;
  }
  function listaAulas(m) {
    let tema = null;
    return aulasDo(m.id).map((a, i) => {
      const titulo = a.tp && a.tp !== tema ? `<h3 class="grupo">${esc(a.tp)}</h3>` : '';
      tema = a.tp;
      return titulo + linhaAula(a, i);
    }).join('');
  }
  function paginaLiberada(m) {
    const lista = aulasDo(m.id);
    const pdf = estado.segredo?.modulos?.[m.id]?.pdf;
    const vis = vistas(m.id);
    const iRet = retomar(m.id);
    const comecou = lista.some((a) => prog[a.id]);
    return `<div class="pagina-capa" id="pagina-capa">
        <img src="${esc(m.img)}" alt="" width="720" height="402">
        <div class="player" id="player" hidden></div>
        <button class="fechar" type="button" data-fechar aria-label="Fechar">${ico('x')}</button>
      </div>
      <div class="pagina-corpo" id="pagina-corpo">
        <button class="fechar fechar-corpo" type="button" data-fechar aria-label="Fechar">${ico('x')}</button>
        <div class="aula-atual" id="aula-atual" hidden></div>
        <h2 class="pagina-titulo" id="modulo-titulo">${esc(m.titulo)}</h2>
        <p class="pagina-meta">${linhaMeta([m.rotulo, `${m.aulas} aulas`, tempo(m.minutos), vis ? `${vis} assistidas` : ''])}</p>
        <div class="pagina-acoes">
          <button class="botao botao-principal" type="button" data-acao="tocar" data-i="${iRet}">${ico('play-fill')}<span>${comecou ? `Continuar: aula ${iRet + 1}` : 'Assistir a aula 1'}</span></button>
          ${pdf ? `<button class="botao botao-secundario" type="button" data-acao="pdf" data-id="${esc(pdf)}">${ico('book-open-text')}<span>Apostila do módulo</span></button>` : ''}
        </div>
        <div class="aulas" id="aulas">${listaAulas(m)}</div>
      </div>`;
  }
  // revelar: a página acabou de ser liberada pela senha (as aulas entram uma a uma e o foco vai pro "Assistir")
  async function abrirModulo(id, { tocarVid, tocarI, revelar } = {}) {
    const m = D.modulos.find((x) => x.id === id);
    if (!m) return;
    const pag = $('#pagina-modulo');
    pararTocador();
    if (estado.liberado) {
      try { await garantirSegredo(); } catch (e) { aviso('Não consegui abrir as aulas agora. Confira a internet e tente de novo.'); return; }
      pag.innerHTML = paginaLiberada(m);
    } else {
      pag.innerHTML = paginaBloqueada(m);
    }
    tocador.m = m;
    pag.scrollTop = 0;
    if (!aberta('modulo')) abrirCamada('modulo', { aoFechar: fecharModulo, foco: '.fechar' });
    if (!estado.liberado) return;
    if (revelar) {
      $('#aulas', pag)?.classList.add('chegando');
      $('[data-acao="tocar"]', pag)?.focus({ preventScroll: true });
    }
    const i = tocarVid ? aulasDo(m.id).findIndex((a) => a.id === tocarVid) : (Number.isInteger(tocarI) ? tocarI : -1);
    if (i >= 0 && i < aulasDo(m.id).length) tocar(i);
  }
  function fecharModulo() {
    pararTocador();
    renderTudo();
  }

  let ytCarga = null;
  function carregarYT() {
    if (window.YT && window.YT.Player) return Promise.resolve(window.YT);
    if (!ytCarga) {
      ytCarga = new Promise((res, rej) => {
        const antes = window.onYouTubeIframeAPIReady;
        window.onYouTubeIframeAPIReady = () => { if (typeof antes === 'function') antes(); res(window.YT); };
        const s = document.createElement('script');
        s.src = 'https://www.youtube.com/iframe_api';
        s.async = true;
        s.onerror = () => { ytCarga = null; rej(new Error('yt')); };
        document.head.append(s);
        setTimeout(() => rej(new Error('yt demorou')), 12000);
      });
    }
    return ytCarga;
  }
  function gravarPosicao() {
    const { yt, m, i } = tocador;
    if (!yt || !yt.getCurrentTime || !m) return;
    const a = aulasDo(m.id)[i];
    if (!a) return;
    const t = yt.getCurrentTime() || 0;
    const d = yt.getDuration() || a.d;
    const p = prog[a.id] || (prog[a.id] = {});
    p.t = Math.floor(t);
    p.em = Date.now();
    const virou = d && t / d > 0.92 && !p.v;
    if (virou) p.v = 1;
    salvarProg();
    if (virou) atualizarAulaNaTela(i);
    else {
      const barra = $(`.aula[data-i="${i}"] .progresso i`);
      if (barra) barra.style.setProperty('--p', pct(a) + '%');
    }
  }
  function pararTocador() {
    clearInterval(tocador.relogio);
    clearInterval(tocador.ponteiro);
    clearTimeout(tocador.tInicio);
    sairDaCheia();
    if (tocador.yt) {
      try { gravarPosicao(); tocador.yt.destroy(); } catch (e) { /* já foi */ }
    }
    tocador.yt = null;
    tocador.i = -1;
    // o player reserva (iframe simples, sem a API) não tem destroy: esvaziar o player para o vídeo
    const pl = $('#player');
    if (pl) pl.textContent = '';
  }

  // ---------- player próprio: o vídeo do YouTube fica por baixo e nenhum botão dele recebe toque ----------
  // a aluna usa só os nossos controles: tocar e pausar, a barra do tempo, volume (menos e mais) e tela cheia
  const ehIOS = /iPad|iPhone|iPod/.test(navigator.userAgent) || (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1);
  const fmtTempo = (s) => {
    const t = Math.max(0, Math.floor(s || 0));
    const h = Math.floor(t / 3600), m = Math.floor((t % 3600) / 60), x = t % 60;
    return (h ? `${h}:${String(m).padStart(2, '0')}` : String(m)) + ':' + String(x).padStart(2, '0');
  };
  const duracaoAtual = () => {
    const yt = tocador.yt;
    const d = yt && yt.getDuration ? yt.getDuration() : 0;
    return d || (tocador.m && aulasDo(tocador.m.id)[tocador.i]?.d) || 0;
  };
  function montarTela(player) {
    player.innerHTML = `<div class="tela" id="tela" data-estado="carregando">
        <div id="yt-alvo"></div>
        <div class="tela-veu" data-tela="veu"></div>
        <button class="tela-centro" type="button" data-tela="tocar" aria-label="Tocar ou pausar">${ico('play-fill', 'i-tocar')}${ico('pause-fill', 'i-pausar')}</button>
        <div class="tela-fim"></div>
        <div class="tela-barra">
          <button class="tela-btn" type="button" data-tela="tocar" aria-label="Tocar ou pausar">${ico('play-fill', 'i-tocar')}${ico('pause-fill', 'i-pausar')}</button>
          <span class="tela-tempo" id="tela-tempo">0:00</span>
          <input class="tela-linha" id="tela-linha" type="range" min="0" max="1000" step="1" value="0" aria-label="Posição do vídeo">
          ${ehIOS ? '' : `<div class="tela-volume" role="group" aria-label="Volume">
            <button class="tela-btn" type="button" data-tela="vol-menos" aria-label="Diminuir o volume">${ico('minus')}</button>
            ${ico('speaker-simple-high')}
            <button class="tela-btn" type="button" data-tela="vol-mais" aria-label="Aumentar o volume">${ico('plus')}</button>
          </div>`}
          <button class="tela-btn" type="button" data-tela="cheia" aria-label="Tela cheia">${ico('corners-out', 'i-abrir')}${ico('corners-in', 'i-fechar')}</button>
        </div>
        <div class="tela-aviso" id="tela-aviso" aria-live="polite"></div>
      </div>`;
    const tela = $('#tela', player);
    tela.addEventListener('click', aoTocarTela);
    tela.addEventListener('pointerdown', (e) => { tela._toque = e.pointerType === 'touch'; }, { passive: true });
    tela.addEventListener('pointermove', (e) => { if (e.pointerType !== 'touch') acordarTela(); }, { passive: true });
    // no computador, dois cliques no vídeo põem ou tiram a tela cheia, como no YouTube
    tela.addEventListener('dblclick', (e) => {
      if (tela._toque || !e.target.closest('[data-tela="veu"]')) return;
      alternarCheia();
      // cada um dos dois cliques pausou ou voltou o vídeo: ele fica como estava antes do primeiro
      const yt = tocador.yt, antes = tela._antes;
      if (yt && yt.playVideo && antes && Date.now() - antes.em < 800) { if (antes.tocando) yt.playVideo(); else yt.pauseVideo(); }
    });
    const linha = $('#tela-linha', tela);
    linha.addEventListener('input', () => { tela._arrastando = true; pintarTempo((Number(linha.value) / 1000) * duracaoAtual()); acordarTela(); });
    linha.addEventListener('change', () => {
      tela._arrastando = false;
      const yt = tocador.yt;
      if (yt && yt.seekTo) yt.seekTo((Number(linha.value) / 1000) * duracaoAtual(), true);
      acordarTela(4500);
    });
    return tela;
  }
  function pintarTempo(t) {
    const tela = $('#tela');
    if (!tela) return;
    const d = duracaoAtual();
    $('#tela-tempo').textContent = `${fmtTempo(t)} / ${fmtTempo(d)}`;
    const linha = $('#tela-linha');
    if (!tela._arrastando && d) linha.value = String(Math.round((t / d) * 1000));
    linha.style.setProperty('--p', `${d ? Math.min(100, (t / d) * 100) : 0}%`);
  }
  function estadoTela(nome) { const tela = $('#tela'); if (tela) tela.dataset.estado = nome; }
  let tAvisoTela = 0;
  function avisoTela(txt) {
    const el = $('#tela-aviso');
    if (!el) return;
    el.textContent = txt;
    el.classList.add('visivel');
    clearTimeout(tAvisoTela);
    tAvisoTela = setTimeout(() => el.classList.remove('visivel'), 1300);
  }
  // a barra some depois de um tempo parada; depois de cada play fica pelo menos 4,5 s, que é o tempo
  // em que o YouTube mostra o "pausar" dele no meio (o nosso botão do meio fica por cima)
  let tOcioso = 0, ociosoEm = 0;
  function acordarTela(ms = 2600) {
    const tela = $('#tela');
    if (!tela) return;
    tela.removeAttribute('data-ocioso');
    ociosoEm = Math.max(ociosoEm, Date.now() + ms);
    clearTimeout(tOcioso);
    tOcioso = setTimeout(() => { if (tela.dataset.estado === 'tocando') tela.setAttribute('data-ocioso', ''); }, ociosoEm - Date.now());
  }
  function esconderControles() {
    const tela = $('#tela');
    if (!tela) return;
    clearTimeout(tOcioso);
    ociosoEm = 0;
    tela.setAttribute('data-ocioso', '');
  }
  // o iframe do YouTube fica inerte (nem toque, nem Tab, nem leitor de tela chegam nele);
  // só fica livre no caso do celular que exige o primeiro toque no próprio vídeo
  function videoLivre(livre) {
    const tela = $('#tela');
    if (!tela) return;
    tela.toggleAttribute('data-livre', livre);
    const f = $('iframe', tela);
    if (f) { f.tabIndex = -1; f.inert = !livre; }
  }
  // celular que não deixa o vídeo começar sozinho (o iPhone exige o primeiro toque no próprio vídeo):
  // só nesse caso o toque passa pro vídeo até ele começar, e depois volta a ficar bloqueado
  function conferirInicio() {
    clearTimeout(tocador.tInicio);
    tocador.tInicio = setTimeout(() => {
      const yt = tocador.yt, tela = $('#tela');
      if (!yt || !tela || !yt.getPlayerState) return;
      const S = window.YT.PlayerState;
      const st = yt.getPlayerState();
      if (st !== S.PLAYING && st !== S.BUFFERING) { videoLivre(true); avisoTela('Toque no vídeo pra começar'); }
    }, 1600);
  }
  function aoTocarTela(e) {
    const b = e.target.closest('[data-tela]');
    if (!b) return;
    const tela = $('#tela');
    const yt = tocador.yt;
    const acao = b.dataset.tela;
    // no celular, com o vídeo tocando, o toque no vídeo só mostra ou esconde os controles (como no app do
    // YouTube); pausar fica no botão do meio ou no da barra. No computador, o clique no vídeo pausa e volta.
    if (acao === 'veu' && tela._toque && tela.dataset.estado === 'tocando') {
      if (tela.hasAttribute('data-ocioso')) acordarTela(); else esconderControles();
      return;
    }
    if (acao === 'veu' && tela.dataset.estado === 'fim') return; // no fim, só os botões da tela de fim
    acordarTela();
    if (!yt || !yt.getPlayerState) return;
    const S = window.YT.PlayerState;
    if (acao === 'veu' || acao === 'tocar') {
      const st = yt.getPlayerState();
      const tocando = st === S.PLAYING || st === S.BUFFERING;
      if (acao === 'veu' && (!tela._antes || Date.now() - tela._antes.em > 400)) tela._antes = { tocando, em: Date.now() };
      if (tocando) yt.pauseVideo();
      else { yt.playVideo(); conferirInicio(); }
    } else if (acao === 'de-novo') {
      yt.seekTo(0, true);
      yt.playVideo();
    } else if (acao === 'vol-menos' || acao === 'vol-mais') {
      if (yt.isMuted && yt.isMuted()) yt.unMute();
      const v = Math.max(0, Math.min(100, (yt.getVolume() || 0) + (acao === 'vol-mais' ? 10 : -10)));
      yt.setVolume(v);
      avisoTela(v === 0 ? 'Sem som' : `Volume ${v}%`);
    } else if (acao === 'cheia') {
      alternarCheia();
    }
  }
  const telaCheiaAgora = () => document.fullscreenElement || document.webkitFullscreenElement || $('.tela.tela-cheia');
  function alternarCheia() {
    const tela = $('#tela');
    if (!tela) return;
    if (telaCheiaAgora()) { sairDaCheia(); return; }
    const pedir = tela.requestFullscreen || tela.webkitRequestFullscreen;
    const reserva = () => { tela.classList.add('tela-cheia'); atualizarCheia(); };
    if (!pedir) { reserva(); return; }
    try {
      Promise.resolve(pedir.call(tela))
        .then(() => { try { screen.orientation.lock('landscape').catch(() => {}); } catch (e) { /* sem giro automático */ } })
        .catch(reserva);
    } catch (e) { reserva(); }
  }
  function sairDaCheia() {
    if (document.fullscreenElement || document.webkitFullscreenElement) {
      try { (document.exitFullscreen || document.webkitExitFullscreen).call(document); } catch (e) { /* já saiu */ }
    }
    $$('.tela.tela-cheia').forEach((t) => t.classList.remove('tela-cheia'));
    try { screen.orientation.unlock(); } catch (e) { /* nada a destravar */ }
    atualizarCheia();
  }
  function atualizarCheia() {
    const tela = $('#tela');
    if (!tela) return;
    const on = Boolean(telaCheiaAgora());
    tela.toggleAttribute('data-cheia', on);
    const b = $('[data-tela="cheia"]', tela);
    if (b) b.setAttribute('aria-label', on ? 'Sair da tela cheia' : 'Tela cheia');
  }
  document.addEventListener('fullscreenchange', atualizarCheia);
  document.addEventListener('webkitfullscreenchange', atualizarCheia);

  function aoMudarEstado(ev) {
    const S = window.YT.PlayerState;
    clearInterval(tocador.relogio);
    clearInterval(tocador.ponteiro);
    const tela = $('#tela');
    if (ev.data === S.PLAYING) {
      tocador.relogio = setInterval(gravarPosicao, 5000);
      tocador.ponteiro = setInterval(() => { const yt = tocador.yt; if (yt && yt.getCurrentTime) pintarTempo(yt.getCurrentTime()); }, 500);
      clearTimeout(tocador.tInicio);
      if (tela) videoLivre(false);
      estadoTela('tocando');
      acordarTela(4500);
    } else if (ev.data === S.BUFFERING) {
      estadoTela('carregando');
    } else if (ev.data === S.ENDED) {
      estadoTela('fim');
      const a = aulasDo(tocador.m.id)[tocador.i];
      if (a) { prog[a.id] = { ...(prog[a.id] || {}), v: 1, t: 0, em: Date.now() }; salvarProg(); atualizarAulaNaTela(tocador.i); }
      montarFim();
    } else {
      if (ev.data === S.PAUSED) gravarPosicao();
      estadoTela('pausado');
      acordarTela();
    }
    const yt = tocador.yt;
    if (yt && yt.getCurrentTime) pintarTempo(ev.data === S.ENDED ? duracaoAtual() : yt.getCurrentTime());
  }
  // no fim da aula a tela fica escura (o YouTube põe sugestões de outros vídeos por trás) e oferece
  // ver de novo ou seguir; o "Próxima aula" usa o mesmo caminho do botão de baixo do vídeo
  function montarFim() {
    const caixa = $('#tela .tela-fim');
    if (!caixa) return;
    const m = tocador.m, i = tocador.i;
    const prox = proxima({ m, i, a: aulasDo(m.id)[i] });
    caixa.innerHTML = `<div class="tela-fim-miolo">
        <p class="tela-fim-titulo">${ico('check-circle-fill')}<span>Aula assistida</span></p>
        <div class="tela-fim-acoes">
          <button class="botao botao-secundario" type="button" data-tela="de-novo">${ico('arrow-counter-clockwise')}<span>Ver de novo</span></button>
          ${prox ? `<button class="botao botao-principal" type="button" data-acao="proxima"><span>${prox.m === m ? 'Próxima aula' : 'Próximo módulo'}</span>${ico('caret-right')}</button>` : ''}
        </div>
      </div>`;
  }
  function atualizarAulaNaTela(i) {
    const m = tocador.m;
    const a = aulasDo(m.id)[i];
    const velha = $(`.aula[data-i="${i}"]`);
    if (a && velha) {
      const tinhaFoco = document.activeElement === velha;
      velha.outerHTML = linhaAula(a, i);
      const nova = $(`.aula[data-i="${i}"]`);
      if (i === tocador.i) nova.setAttribute('aria-current', 'true');
      if (tinhaFoco) nova.focus({ preventScroll: true });
    }
    if (i === tocador.i) atualizarBotaoFeito();
  }
  // o botão "Marcar como assistida" muda no lugar (recriar tiraria o foco de quem usa teclado ou leitor de tela)
  function atualizarBotaoFeito() {
    const a = aulasDo(tocador.m.id)[tocador.i];
    const b = $('#aula-atual [data-acao="feito"]');
    if (!a || !b) return;
    const vista = Boolean(prog[a.id]?.v);
    b.setAttribute('aria-pressed', String(vista));
    $('use', b)?.setAttribute('href', `#i-${vista ? 'check-circle-fill' : 'check-circle'}`);
    $('span', b).textContent = vista ? 'Assistida' : 'Marcar como assistida';
  }
  function renderAulaAtual() {
    const { m, i } = tocador;
    const a = aulasDo(m.id)[i];
    const caixa = $('#aula-atual');
    if (!a || !caixa) return;
    const vista = !!prog[a.id]?.v;
    const prox = proxima({ m, i, a });
    caixa.hidden = false;
    caixa.innerHTML = `<h3>${i + 1}. ${esc(a.t)}</h3>
      <div class="aula-atual-acoes">
        <button class="botao botao-secundario botao-feito" type="button" data-acao="feito" aria-pressed="${vista}">${ico(vista ? 'check-circle-fill' : 'check-circle')}<span>${vista ? 'Assistida' : 'Marcar como assistida'}</span></button>
        ${prox ? `<button class="botao botao-principal" type="button" data-acao="proxima"><span>${prox.m === m ? 'Próxima aula' : 'Próximo módulo'}</span>${ico('caret-right')}</button>` : ''}
      </div>`;
  }
  async function tocar(i) {
    const m = tocador.m;
    const a = aulasDo(m.id)[i];
    if (!a) return;
    if (tocador.yt) gravarPosicao();
    tocador.i = i;
    const capa = $('#pagina-capa');
    const player = $('#player');
    capa.classList.add('tocando');
    player.hidden = false;
    $('#pagina-corpo').classList.add('tocando');
    $$('.aula[aria-current]').forEach((x) => x.removeAttribute('aria-current'));
    $(`.aula[data-i="${i}"]`)?.setAttribute('aria-current', 'true');
    const p = prog[a.id] || (prog[a.id] = {});
    p.em = Date.now();
    salvarProg();
    renderAulaAtual();
    // se o botão que tinha o foco sumiu (o X da capa ou o "Assistir" escondem ao tocar), o foco vai pro título da aula
    const ativo = document.activeElement;
    if (!ativo || ativo === document.body || !document.contains(ativo) || ativo.offsetParent === null) {
      const h = $('#aula-atual h3');
      if (h) { h.tabIndex = -1; h.focus({ preventScroll: true }); }
    }
    $('#pagina-modulo').scrollTo({ top: 0, behavior: quieto() ? 'auto' : 'smooth' });
    const inicio = p.v ? 0 : Math.floor(p.t || 0);
    try {
      const YT = await carregarYT();
      if (tocador.m !== m || tocador.i !== i) return;
      if (tocador.yt && tocador.yt.loadVideoById && $('#tela')) {
        estadoTela('carregando');
        pintarTempo(inicio);
        tocador.yt.loadVideoById({ videoId: a.id, startSeconds: inicio });
        conferirInicio();
      } else {
        montarTela(player);
        pintarTempo(inicio);
        tocador.yt = new YT.Player('yt-alvo', {
          host: 'https://www.youtube-nocookie.com',
          videoId: a.id,
          width: '100%',
          height: '100%',
          // sem os controles do YouTube, sem atalhos de teclado, sem o botão de tela cheia dele e sem anotações
          playerVars: { autoplay: 1, controls: 0, disablekb: 1, fs: 0, rel: 0, iv_load_policy: 3, cc_load_policy: 0, playsinline: 1, start: inicio, origin: location.origin },
          events: { onReady: () => { videoLivre(false); conferirInicio(); }, onStateChange: aoMudarEstado },
        });
        videoLivre(false);
      }
    } catch (e) {
      // sem a API do YouTube: o vídeo toca do mesmo jeito (sem os controles do YouTube), só não guarda onde parou
      // (se ela já fechou o módulo ou trocou de aula enquanto esperava, não põe nada pra tocar)
      if (tocador.m !== m || tocador.i !== i || !aberta('modulo')) return;
      player.innerHTML = `<div class="tela" data-livre data-estado="tocando"><iframe src="https://www.youtube-nocookie.com/embed/${encodeURIComponent(a.id)}?autoplay=1&controls=0&disablekb=1&fs=0&rel=0&iv_load_policy=3&playsinline=1&start=${inicio}" title="${esc(a.t)}" allow="autoplay; encrypted-media"></iframe></div>`;
    }
  }
  $('#pagina-modulo').addEventListener('click', (e) => {
    const alvo = e.target.closest('[data-acao], .aula');
    if (!alvo) return;
    const acao = alvo.dataset.acao;
    if (!acao) { tocar(Number(alvo.dataset.i)); return; }
    if (acao === 'tocar') tocar(Number(alvo.dataset.i));
    else if (acao === 'pdf') abrirPdf(alvo.dataset.id);
    else if (acao === 'liberar') abrirLiberar();
    else if (acao === 'feito') {
      const a = aulasDo(tocador.m.id)[tocador.i];
      if (!a) return;
      const p = prog[a.id] || (prog[a.id] = {});
      p.v = p.v ? 0 : 1;
      if (p.v) p.t = 0;
      p.em = Date.now();
      salvarProg();
      atualizarAulaNaTela(tocador.i);
    } else if (acao === 'proxima') {
      const m = tocador.m;
      const prox = proxima({ m, i: tocador.i, a: aulasDo(m.id)[tocador.i] });
      if (!prox) return;
      if (prox.m === m) tocar(prox.i);
      else abrirModulo(prox.m.id, { tocarVid: prox.a.id });
    }
  });

  // ---------- leitor de PDF (pdf.js, páginas desenhadas só perto da tela) ----------
  let pdfjsCarga = null;
  function carregarPdfjs() {
    if (window.pdfjsLib) return Promise.resolve(window.pdfjsLib);
    if (!pdfjsCarga) {
      pdfjsCarga = new Promise((res, rej) => {
        const s = document.createElement('script');
        s.src = 'vendor/pdf.min.js';
        s.onload = () => { window.pdfjsLib.GlobalWorkerOptions.workerSrc = 'vendor/pdf.worker.min.js'; res(window.pdfjsLib); };
        s.onerror = () => { pdfjsCarga = null; rej(new Error('pdfjs')); };
        document.head.append(s);
      });
    }
    return pdfjsCarga;
  }
  const L = { id: null, info: null, doc: null, total: 0, atual: 0, ar: 0.7071, w: 0, zoom: false, obs: null, tarefas: new Map(), blob: null, geracao: 0 };
  const areaPdf = $('#leitor-paginas');
  function estadoLeitor(texto, p = null, erro = false) {
    const caixa = $('#leitor-estado');
    if (!texto) { caixa.hidden = true; return; }
    caixa.hidden = false;
    $('#leitor-estado-txt').textContent = texto;
    const barra = $('#leitor-barra');
    barra.hidden = p == null;
    if (p != null) barra.style.setProperty('--p', String(p));
    $('#leitor-tentar').hidden = !erro;
  }
  async function abrirPdf(id) {
    let info = D.gratis.find((g) => g.id === id);
    if (info) info = { titulo: info.titulo, paginas: info.paginas, arq: info.arq, cifrado: false };
    else {
      if (!estado.liberado) { abrirLiberar(); return; }
      try { await garantirSegredo(); } catch (e) { aviso('Não consegui abrir agora. Confira a internet e tente de novo.'); return; }
      info = estado.segredo.pdfs?.[id];
      if (!info) { aviso('Não achei essa apostila.'); return; }
    }
    L.id = id;
    L.info = info;
    $('#leitor-titulo').textContent = info.titulo;
    $('#leitor-pagina').textContent = '';
    areaPdf.innerHTML = '';
    if (!aberta('leitor')) abrirCamada('leitor', { aoFechar: fecharLeitor, foco: '[data-fechar]' });
    carregarDoc();
  }
  async function carregarDoc() {
    const info = L.info;
    const geracao = ++L.geracao;
    estadoLeitor(info.cifrado ? 'Baixando a apostila…' : 'Abrindo a apostila…', info.cifrado ? 0 : null);
    try {
      const pdfjs = await carregarPdfjs();
      let fonte;
      if (info.cifrado) {
        const buf = await baixar(info.arq, (p) => {
          if (geracao !== L.geracao) return;
          $('#leitor-barra').style.setProperty('--p', String(p));
          $('#leitor-estado-txt').textContent = `Baixando a apostila… ${Math.round(p * 100)}%`;
        });
        if (geracao !== L.geracao) return;
        estadoLeitor('Abrindo a apostila…');
        const plano = await decifrar(buf, estado.chave);
        if (L.blob) URL.revokeObjectURL(L.blob);
        L.blob = URL.createObjectURL(new Blob([plano], { type: 'application/pdf' }));
        fonte = { data: new Uint8Array(plano) };
      } else {
        fonte = { url: info.arq, disableAutoFetch: true, rangeChunkSize: 262144 };
      }
      const doc = await pdfjs.getDocument(fonte).promise;
      if (geracao !== L.geracao) { doc.destroy(); return; }
      L.doc = doc;
      L.total = doc.numPages;
      const vp = (await doc.getPage(1)).getViewport({ scale: 1 });
      L.ar = vp.width / vp.height;
      montarPaginas();
      estadoLeitor(null);
      // (22/10) sem botão de baixar: a apostila é lida aqui dentro (pedido do Luan)
      const salva = lidas[L.id];
      if (salva > 1 && salva <= L.total) { irPara(salva); aviso(`Continuando da página ${salva}`); }
      areaPdf.focus({ preventScroll: true });
    } catch (e) {
      if (geracao !== L.geracao) return;
      estadoLeitor('Não consegui abrir a apostila. Confira a internet e tente de novo.', null, true);
    }
  }
  const alturaPg = () => L.w / L.ar + 10;
  function montarPaginas() {
    const base = Math.min(areaPdf.clientWidth - 16, 920);
    L.w = Math.round(L.zoom ? base * 1.8 : base);
    areaPdf.style.setProperty('--pg-w', L.w + 'px');
    areaPdf.style.setProperty('--pg-ar', String(L.ar));
    let h = '';
    for (let n = 1; n <= L.total; n++) h += `<div class="pg" data-n="${n}"></div>`;
    areaPdf.innerHTML = h;
    for (const t of L.tarefas.values()) t.cancel();
    L.tarefas.clear();
    if (L.obs) L.obs.disconnect();
    L.obs = new IntersectionObserver((entradas) => {
      for (const en of entradas) {
        const n = Number(en.target.dataset.n);
        if (en.isIntersecting) desenhar(en.target, n);
        else apagar(en.target, n);
      }
    }, { root: areaPdf, rootMargin: '120% 0px' });
    $$('.pg', areaPdf).forEach((pg) => L.obs.observe(pg));
    L.atual = 0;
    numeroPagina();
  }
  async function desenhar(pg, n) {
    if (pg.querySelector('canvas') || L.tarefas.has(n) || !L.doc) return;
    const geracao = L.geracao, w = L.w;
    let tarefa = null;
    try {
      const page = await L.doc.getPage(n);
      if (geracao !== L.geracao || w !== L.w || !pg.isConnected) return;
      const vp1 = page.getViewport({ scale: 1 });
      const dpr = Math.min(window.devicePixelRatio || 1, L.zoom ? 2 : 2.5);
      const vp = page.getViewport({ scale: (w * dpr) / vp1.width });
      const canvas = document.createElement('canvas');
      canvas.width = Math.floor(vp.width);
      canvas.height = Math.floor(vp.height);
      tarefa = page.render({ canvasContext: canvas.getContext('2d', { alpha: false }), viewport: vp });
      L.tarefas.set(n, tarefa);
      await tarefa.promise;
      if (L.tarefas.get(n) === tarefa) L.tarefas.delete(n);
      if (geracao !== L.geracao || w !== L.w || !pg.isConnected) return;
      const ar = vp1.width / vp1.height;
      if (Math.abs(ar - L.ar) > 0.01) pg.style.setProperty('--pg-ar', String(ar));
      pg.append(canvas);
    } catch (e) {
      if (tarefa && L.tarefas.get(n) === tarefa) L.tarefas.delete(n);
    }
  }
  function apagar(pg, n) {
    const t = L.tarefas.get(n);
    if (t) { t.cancel(); L.tarefas.delete(n); }
    const c = pg.querySelector('canvas');
    if (c) { c.width = 0; c.height = 0; c.remove(); }
  }
  function numeroPagina() {
    if (!L.total) return;
    const n = Math.min(L.total, Math.max(1, Math.floor((areaPdf.scrollTop + areaPdf.clientHeight * 0.35) / alturaPg()) + 1));
    if (n === L.atual) return;
    L.atual = n;
    $('#leitor-pagina').textContent = `${n} de ${L.total}`;
    lidas[L.id] = n;
    salvarLidas();
  }
  function irPara(n) { areaPdf.scrollTop = (n - 1) * alturaPg(); numeroPagina(); }
  areaPdf.addEventListener('scroll', () => requestAnimationFrame(numeroPagina), { passive: true });
  $('#leitor-zoom').addEventListener('click', () => {
    if (!L.doc) return;
    const atual = L.atual || 1;
    L.zoom = !L.zoom;
    $('.leitor').toggleAttribute('data-zoom', L.zoom);
    $('#leitor-zoom').setAttribute('aria-label', L.zoom ? 'Diminuir a letra' : 'Aumentar a letra');
    montarPaginas();
    irPara(atual);
  });
  $('#leitor-tentar').addEventListener('click', () => carregarDoc());
  function fecharLeitor() {
    L.geracao++;
    if (L.obs) { L.obs.disconnect(); L.obs = null; }
    for (const t of L.tarefas.values()) t.cancel();
    L.tarefas.clear();
    if (L.doc) { L.doc.destroy(); L.doc = null; }
    L.total = 0;
    L.zoom = false;
    $('.leitor').removeAttribute('data-zoom');
    $('#leitor-zoom').setAttribute('aria-label', 'Aumentar a letra');
    if (L.blob) { const u = L.blob; L.blob = null; setTimeout(() => URL.revokeObjectURL(u), 2000); }
    guarda.gravar('paginas', lidas);
    setTimeout(() => { if (!aberta('leitor')) areaPdf.innerHTML = ''; }, 380);
    renderGratis();
    renderBonus();
  }

  // ---------- aviso rápido ----------
  let tAviso = 0;
  function aviso(txt) {
    const el = $('#aviso');
    el.textContent = txt;
    el.classList.add('visivel');
    clearTimeout(tAviso);
    tAviso = setTimeout(() => el.classList.remove('visivel'), 2600);
  }

  // ---------- setas das fileiras (computador) ----------
  function ligarSetas() {
    for (const caixa of $$('.trilho-caixa')) {
      const trilho = $('.trilho', caixa);
      caixa.insertAdjacentHTML('beforeend',
        `<button class="seta seta-esq" type="button" tabindex="-1" aria-label="Voltar">${ico('caret-left')}</button>`
        + `<button class="seta seta-dir" type="button" tabindex="-1" aria-label="Avançar">${ico('caret-right')}</button>`);
      const esq = $('.seta-esq', caixa), dir = $('.seta-dir', caixa);
      const andar = (s) => trilho.scrollBy({ left: s * trilho.clientWidth * 0.85, behavior: quieto() ? 'auto' : 'smooth' });
      esq.addEventListener('click', () => andar(-1));
      dir.addEventListener('click', () => andar(1));
      caixa._setas = () => {
        esq.disabled = trilho.scrollLeft < 8;
        dir.disabled = trilho.scrollLeft + trilho.clientWidth >= trilho.scrollWidth - 8;
      };
      trilho.addEventListener('scroll', () => requestAnimationFrame(caixa._setas), { passive: true });
      caixa._setas();
    }
    window.addEventListener('resize', () => $$('.trilho-caixa').forEach((c) => c._setas?.()));
  }

  // ---------- cliques da página ----------
  $('#fileiras').addEventListener('click', (e) => {
    const c = e.target.closest('.cartao');
    if (!c) return;
    const tipo = c.dataset.tipo;
    if (tipo === 'pdf') abrirPdf(c.dataset.id);
    else if (tipo === 'modulo') abrirModulo(c.dataset.id);
    else if (tipo === 'aula') {
      // aula bloqueada leva direto pra folha de liberar; liberada abre o módulo já tocando ela
      if (!estado.liberado) { abrirLiberar(); return; }
      if (c.dataset.vid) abrirModulo(c.dataset.mod, { tocarVid: c.dataset.vid });
      else abrirModulo(c.dataset.mod, { tocarI: Number(c.dataset.i) });
    }
  });
  $('#destaque-acoes').addEventListener('click', async (e) => {
    const b = e.target.closest('[data-acao]');
    if (!b) return;
    const acao = b.dataset.acao;
    if (acao === 'ler-gratis') abrirPdf(D.gratis[0].id);
    else if (acao === 'liberar') abrirLiberar();
    else if (acao === 'modulos') irPraAulas();
    else if (acao === 'continuar' || acao === 'primeira') {
      try { await garantirSegredo(); } catch (err) { aviso('Não consegui abrir as aulas agora. Confira a internet e tente de novo.'); return; }
      // depois que o cofre chegou o progresso é conhecido: os dois botões retomam de onde ela parou, se houver
      const c = continuar()[0];
      if (c) abrirModulo(c.m.id, { tocarVid: c.a.id });
      else { const m = D.modulos[0]; abrirModulo(m.id, { tocarVid: aulasDo(m.id)[0]?.id }); }
    }
  });
  $('#selo').addEventListener('click', () => (estado.liberado ? irPraAulas() : abrirLiberar()));
  $('#camada-liberar').addEventListener('click', (e) => { if (e.target.closest('[data-acao="copiar-pix"]')) copiarPix(); });
  $('#esquecer').addEventListener('click', () => {
    if (!confirm('Esquecer a senha neste aparelho? Pra ver as aulas de novo, vai precisar digitar a senha.')) return;
    guarda.apagar('chave');
    location.reload();
  });
  const topo = $('#topo');
  const aoRolar = () => topo.classList.toggle('solido', window.scrollY > 24);
  window.addEventListener('scroll', aoRolar, { passive: true });


  // ---------- certificado: senha própria, o nome dela e o PDF na hora ----------
  // Mesmo modelo e mesmas medidas do certificado que o bot emite (bot-whatsapp/lib/certificado.js). A arte de fundo
  // vem no cofre, trancada com a senha das aulas (montar.mjs); as fontes são públicas (cert/).
  let certLib = null;
  const certEstado = { url: null };
  function carregarScript(src) {
    return new Promise((res, rej) => {
      const s = document.createElement('script');
      s.src = src; s.onload = res; s.onerror = () => rej(new Error(src));
      document.head.append(s);
    });
  }
  function carregarCertLib() {
    if (!certLib) {
      certLib = carregarScript('vendor/pdf-lib-1.17.1.min.js').then(() => carregarScript('vendor/fontkit-1.1.1.umd.min.js'))
        .catch((e) => { certLib = null; throw e; });
    }
    return certLib;
  }
  const MESES = ['janeiro', 'fevereiro', 'março', 'abril', 'maio', 'junho', 'julho', 'agosto', 'setembro', 'outubro', 'novembro', 'dezembro'];
  async function montarCertificado(nome, arteJpg) {
    const { PDFDocument, rgb } = window.PDFLib;
    const A4 = { w: 841.89, h: 595.28 };
    const VERDE = rgb(0.106, 0.227, 0.184), OURO = rgb(0.69, 0.553, 0.247), CINZA = rgb(0.478, 0.455, 0.396), TINTA = rgb(0.235, 0.227, 0.2);
    const OURO_CLARO = rgb(0.8, 0.71, 0.47), CREME = rgb(0.984, 0.973, 0.945);
    const pdf = await PDFDocument.create();
    pdf.registerFontkit(window.fontkit);
    const fonteOpts = { subset: false, features: { liga: false, clig: false, calt: false, dlig: false, hlig: false } };
    const fonte = async (f) => pdf.embedFont(await (await fetch('cert/' + f + '.ttf')).arrayBuffer(), fonteOpts);
    const [cinzel, cormorant, cormorantIt, pinyon] = await Promise.all(['cinzel', 'cormorant', 'cormorant-italic', 'pinyon'].map(fonte));
    const page = pdf.addPage([A4.w, A4.h]);
    page.drawImage(await pdf.embedJpg(arteJpg), { x: 0, y: 0, width: A4.w, height: A4.h });
    const centro = (texto, { f, t, cor, y, esp = 0 }) => {
      let largura = f.widthOfTextAtSize(texto, t);
      if (esp) largura += esp * (texto.length - 1);
      const x = (A4.w - largura) / 2;
      if (!esp) page.drawText(texto, { x, y, size: t, font: f, color: cor });
      else { let cx = x; for (const ch of texto) { page.drawText(ch, { x: cx, y, size: t, font: f, color: cor }); cx += f.widthOfTextAtSize(ch, t) + esp; } }
      return largura;
    };
    centro('SABONETES DE SUCESSO', { f: cinzel, t: 9.5, cor: CINZA, y: 468, esp: 3.4 });
    centro('CERTIFICADO', { f: cinzel, t: 31, cor: VERDE, y: 424, esp: 2.6 });
    centro('DE CONCLUSÃO', { f: cinzel, t: 10.5, cor: OURO, y: 402, esp: 3.2 });
    page.drawLine({ start: { x: 352, y: 386 }, end: { x: 490, y: 386 }, thickness: 0.7, color: OURO_CLARO });
    centro('Certificamos que', { f: cormorantIt, t: 13, cor: CINZA, y: 358 });
    const tamNome = nome.length > 38 ? 22 : nome.length > 28 ? 26 : 30;
    const larguraNome = centro(nome, { f: cormorantIt, t: tamNome, cor: VERDE, y: 322 });
    const meio = A4.w / 2, linha = Math.max(larguraNome / 2 + 26, 165);
    page.drawLine({ start: { x: meio - linha, y: 312 }, end: { x: meio + linha, y: 312 }, thickness: 0.6, color: OURO_CLARO });
    centro('concluiu com êxito o curso Saboaria Artesanal — Sabonetes de Sucesso,', { f: cormorant, t: 13.5, cor: TINTA, y: 286 });
    centro('com carga horária de 40 horas.', { f: cormorant, t: 13.5, cor: TINTA, y: 267 });
    centro('Guia de Saboaria Artesanal · Sabonetes de Frutas · Sabonete de Cacho · Saboaria Terapêutica', { f: cormorant, t: 10, cor: CINZA, y: 238 });
    centro('Sabonetes Líquidos · Materiais e Insumos · Produção para Venda', { f: cormorant, t: 10, cor: CINZA, y: 223 });
    const hoje = new Date();
    const data = `${hoje.getDate()} de ${MESES[hoje.getMonth()]} de ${hoje.getFullYear()}`;
    const colEsq = 258, colDir = 584;
    page.drawText(data, { x: colEsq - cormorant.widthOfTextAtSize(data, 12.5) / 2, y: 150, size: 12.5, font: cormorant, color: TINTA });
    page.drawLine({ start: { x: colEsq - 78, y: 142 }, end: { x: colEsq + 78, y: 142 }, thickness: 0.6, color: OURO_CLARO });
    const rotulo = (texto, cx0, esp) => {
      let cx = cx0 - (cinzel.widthOfTextAtSize(texto, 7.5) + esp * (texto.length - 1)) / 2;
      for (const ch of texto) { page.drawText(ch, { x: cx, y: 129, size: 7.5, font: cinzel, color: CINZA }); cx += cinzel.widthOfTextAtSize(ch, 7.5) + esp; }
    };
    rotulo('DATA DE CONCLUSÃO', colEsq, 1.1);
    page.drawText('Ana Clari', { x: colDir - pinyon.widthOfTextAtSize('Ana Clari', 30) / 2, y: 152, size: 30, font: pinyon, color: VERDE });
    page.drawLine({ start: { x: colDir - 88, y: 142 }, end: { x: colDir + 88, y: 142 }, thickness: 0.6, color: OURO_CLARO });
    rotulo('SABOARIA ARTESANAL DE SUCESSO', colDir, 0.9);
    const mx = (colEsq + colDir) / 2, my = 174;
    const svg = (pontos) => pontos.map(([x, y], i) => `${i ? 'L' : 'M'} ${x.toFixed(2)} ${(A4.h - y).toFixed(2)}`).join(' ') + ' Z';
    const fitaEsq = [[mx - 10, my - 14], [mx - 3, my - 14], [mx - 6, my - 40], [mx - 10.5, my - 34], [mx - 15, my - 38]];
    for (const fita of [fitaEsq, fitaEsq.map(([x, y]) => [2 * mx - x, y])]) page.drawSvgPath(svg(fita), { x: 0, y: A4.h, color: OURO, borderColor: rgb(0.6, 0.47, 0.2), borderWidth: 0.4 });
    for (let i = 0; i < 12; i++) { const a = (i / 12) * Math.PI * 2; page.drawCircle({ x: mx + Math.cos(a) * 17.5, y: my + Math.sin(a) * 17.5, size: 3.4, color: OURO }); }
    page.drawCircle({ x: mx, y: my, size: 17, color: OURO });
    page.drawCircle({ x: mx, y: my, size: 15, color: CREME });
    page.drawCircle({ x: mx, y: my, size: 12, borderColor: OURO_CLARO, borderWidth: 0.6 });
    const estrela = [];
    for (let i = 0; i < 10; i++) { const a = -Math.PI / 2 + (i * Math.PI) / 5; const r = i % 2 === 0 ? 7 : 2.9; estrela.push([mx + Math.cos(a) * r, my + Math.sin(a) * r]); }
    page.drawSvgPath(svg(estrela), { x: 0, y: A4.h, color: OURO });
    return pdf.save();
  }
  async function mostrarPrevia(bytes) {
    try {
      const lib = await carregarPdfjs();
      const doc = await lib.getDocument({ data: bytes.slice(0) }).promise;
      const pg = await doc.getPage(1);
      const cv = $('#cert-previa');
      const largura = Math.min(cv.parentElement.clientWidth || 340, 640) * Math.min(2, window.devicePixelRatio || 1);
      const vp = pg.getViewport({ scale: largura / pg.getViewport({ scale: 1 }).width });
      cv.width = Math.round(vp.width); cv.height = Math.round(vp.height);
      await pg.render({ canvasContext: cv.getContext('2d'), viewport: vp }).promise;
    } catch (e) { /* sem prévia: o botão de baixar resolve */ }
  }
  async function abrirCertificado() {
    if (aberta('certificado')) return;
    $('#cert-erro').textContent = '';
    $('#cert-form').removeAttribute('data-erro');
    $('#cert-form').hidden = false;
    $('#cert-pronto').hidden = true;
    $('#cert-texto').textContent = 'Digite o seu nome do jeito que você quer que ele apareça. O certificado sai na hora, em PDF.';
    const fino = matchMedia('(hover: hover) and (pointer: fine)').matches;
    abrirCamada('certificado', { foco: fino ? '#cert-nome' : null });
    carregarCertLib().catch(() => {});
  }
  function erroCert(txt, campo) {
    const form = $('#cert-form');
    form.setAttribute('data-erro', '');
    $('#cert-erro').textContent = txt;
    if (campo) { campo.focus(); campo.select?.(); }
    if (!quieto()) { form.classList.remove('tremendo'); void form.offsetWidth; form.classList.add('tremendo'); }
  }
  $('#cert-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const nome = $('#cert-nome').value.replace(/\s+/g, ' ').trim();
    if (nome.length < 3) { erroCert('Digite o seu nome do jeito que ele vai aparecer no certificado.', $('#cert-nome')); return; }
    const gerar = $('#cert-gerar');
    gerar.disabled = true;
    gerar.classList.add('carregando');
    $('#cert-erro').textContent = '';
    $('#cert-form').removeAttribute('data-erro');
    try {
      const segredo = await garantirSegredo();
      const arte = await decifrar(await baixar(segredo.cert), estado.chave);
      await carregarCertLib();
      const bytes = await montarCertificado(nome, arte);
      if (certEstado.url) URL.revokeObjectURL(certEstado.url);
      certEstado.url = URL.createObjectURL(new Blob([bytes], { type: 'application/pdf' }));
      const baixarLink = $('#cert-baixar');
      baixarLink.href = certEstado.url;
      baixarLink.download = `Certificado - ${nome.replace(/[\\/:*?"<>|]/g, '')}.pdf`;
      $('#cert-texto').textContent = 'Pronto! Confira o seu nome e baixe o seu certificado.';
      $('#cert-form').hidden = true;
      $('#cert-pronto').hidden = false;
      baixarLink.focus({ preventScroll: true });
      await mostrarPrevia(bytes);
    } catch (err) {
      erroCert('Não consegui gerar agora. Veja se a internet está ligada e tente de novo.');
    } finally {
      gerar.disabled = false;
      gerar.classList.remove('carregando');
    }
  });
  $('#cert-corrigir').addEventListener('click', () => {
    $('#cert-texto').textContent = 'Digite o seu nome do jeito que você quer que ele apareça. O certificado sai na hora, em PDF.';
    $('#cert-pronto').hidden = true;
    $('#cert-form').hidden = false;
    $('#cert-nome').focus();
    $('#cert-nome').select();
  });
  $('#certificado').addEventListener('click', (e) => { if (e.target.closest('[data-acao="certificado"]')) abrirCertificado(); });

  // ---------- início ----------
  function preencherPix() {
    const caixa = $('#pix');
    if (!PAGAMENTO) { caixa.hidden = true; $('#pix-nome').hidden = true; return; }
    $('#pix-chave').textContent = fmtChave(PAGAMENTO.chave, PAGAMENTO.tipo);
    $('.pix-rotulo', caixa).textContent = `Chave ${PAGAMENTO.tipo}`;
    $('#pix-nome').textContent = PAGAMENTO.nota || '';
  }
  // a oferta (mais de R$ 1.000 por 24,90) aparece uma vez por aparelho, na primeira abertura, só pra quem não liberou
  function abrirOferta() {
    if (estado.liberado || guarda.ler('oferta', 0)) return;
    guarda.gravar('oferta', 1);
    abrirCamada('oferta', { foco: '[data-acao="oferta-liberar"]' });
  }
  $('#camada-oferta').addEventListener('click', (e) => {
    if (!e.target.closest('[data-acao="oferta-liberar"]')) return;
    fecharTopo();
    setTimeout(abrirLiberar, 380);
  });
  async function iniciar() {
    preencherPix();
    montarModulos();
    ordenarFileiras();
    ligarSetas();
    renderTudo();
    aoRolar();
    setTimeout(abrirOferta, 900);
    if (!estado.liberado) return;
    try {
      await dadosAtuais();
      estado.chave = await chaveGuardada();
      if (!estado.chave) throw Object.assign(new Error('sem chave'), { name: 'OperationError' });
      estado.segredo = await abrirCofre(estado.chave);
      renderTudo();
    } catch (e) {
      if (e && (e.name === 'OperationError' || e.name === 'DataError' || e instanceof SyntaxError)) {
        // a senha mudou (ou a chave guardada estragou): volta pro bloqueado
        guarda.apagar('chave');
        estado.liberado = false;
        estado.chave = null;
        html.removeAttribute('data-liberado');
        html.removeAttribute('data-ordem');
        ordenarFileiras();
        renderTudo();
      }
      // sem internet: continua com cara de liberado e tenta de novo quando ela abrir uma aula
    }
  }
  iniciar();
})();
