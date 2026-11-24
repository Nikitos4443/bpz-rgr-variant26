// Збирає report/ІП_33_Шульга_Нікіта_РГР_БПЗ.docx із RGR_report.md.
// Титульна сторінка та базові стилі (TNR 14, інтервал 1,5, відступ 1,25 см) — за зразком Lab1_final.docx;
// поля, нумерація сторінок і розмір сторінки — за вимогами практикуму (А4; 25/10/20/20 мм; номер праворуч угорі).
const fs = require("fs");
const path = require("path");
const {
  Document, Packer, Paragraph, TextRun, ImageRun, Table, TableRow, TableCell, Header,
  AlignmentType, HeadingLevel, LevelFormat, WidthType, BorderStyle, ShadingType, PageNumber,
  TableOfContents, VerticalAlign, TabStopType, LeaderType,
} = require("docx");

// Статичний зміст із крапковими лідерами (щоб номери сторінок були у PDF без оновлення полів).
function staticToc() {
  const tocFile = path.join(HERE, "toc.json");
  if (!fs.existsSync(tocFile)) return null;
  const entries = JSON.parse(fs.readFileSync(tocFile, "utf8"));
  return entries.map((e) =>
    new Paragraph({
      spacing: { line: 360, after: 20 },
      tabStops: [{ type: TabStopType.RIGHT, position: TEXT_W, leader: LeaderType.DOT }],
      children: [
        new TextRun({ text: e.title, font: FONT, size: 28, bold: !!e.bold }),
        new TextRun({ text: "\t" + e.page, font: FONT, size: 28 }),
      ],
    })
  );
}

const HERE = __dirname;
const MD = path.join(HERE, "RGR_report.md");
const OUT = process.argv[2] || path.join(HERE, "ІП_33_Шульга_Нікіта_РГР_БПЗ.docx");

const FONT = "Times New Roman";
const MONO = "Courier New";
const TEXT_W = 11906 - 1417 - 567; // ширина тексту, DXA
const IND = 709; // абзацний відступ 1,25 см

// ---------- інлайн-розбір ----------
function unescape(s) {
  return s.replace(/&nbsp;/g, " ").replace(/\\([\\`*_{}\[\]()#+\-.!|$])/g, "$1");
}

function runs(text, base = {}) {
  const out = [];
  const re = /(`[^`]+`|\*\*[^*]+\*\*|\*[^*\s][^*]*\*)/g;
  let last = 0, m;
  const push = (t, extra = {}) => {
    if (!t) return;
    out.push(new TextRun({ text: unescape(t), font: FONT, size: 28, ...base, ...extra }));
  };
  while ((m = re.exec(text))) {
    push(text.slice(last, m.index));
    const tok = m[0];
    if (tok.startsWith("`")) push(tok.slice(1, -1), { font: MONO, size: base.size ? base.size - 2 : 26 });
    else if (tok.startsWith("**")) runs(tok.slice(2, -2), { ...base }).forEach((r) => out.push(r));
    else runs(tok.slice(1, -1), { ...base, italics: true }).forEach((r) => out.push(r));
    last = m.index + tok.length;
  }
  push(text.slice(last));
  return out;
}

// ---------- розміри PNG ----------
function pngSize(buf) {
  return { w: buf.readUInt32BE(16), h: buf.readUInt32BE(20) };
}

// ---------- титульна сторінка (за зразком Lab1_final.docx) ----------
function titlePage() {
  const c = (text, o = {}) =>
    new Paragraph({
      alignment: AlignmentType.CENTER,
      spacing: { after: o.after ?? 40, before: o.before ?? 0 },
      children: [new TextRun({ text, font: FONT, size: 28, bold: !!o.bold })],
    });
  const r = (text, o = {}) =>
    new Paragraph({
      indent: { left: 4500 },
      spacing: { after: 20, before: o.before ?? 0 },
      children: [new TextRun({ text, font: FONT, size: 28, bold: !!o.bold })],
    });
  return [
    c("Міністерство освіти і науки України"),
    c("Національний технічний університет України «Київський політехнічний інститут імені Ігоря Сікорського»"),
    c("Факультет інформатики та обчислювальної техніки"),
    c("Кафедра інформатики та програмної інженерії"),
    c("", { before: 1000 }),
    c("РОЗРАХУНКОВО-ГРАФІЧНА РОБОТА", { bold: true }),
    c("з навчальної дисципліни «Безпека програмного забезпечення»"),
    c("", { before: 500 }),
    c("Тема:"),
    c("АУДИТ ЗАХИЩЕНОСТІ ПРОГРАМНОГО ЗАСТОСУНКУ", { bold: true, after: 40 }),
    c("Варіант 26 — OWASP Juice Shop, профіль «обхід контролю доступу»", { after: 700 }),
    r("Виконав:", { bold: true }),
    r("Студент 4 курсу, гр. ІП-33"),
    r("Шульга Нікіта Сергійович"),
    r("Перевірив:", { bold: true, before: 160 }),
    r("Соколовський В. В."),
    c("", { before: 700 }),
    c("Київ – 2026"),
  ];
}

// ---------- таблиці ----------
const BORDER = { style: BorderStyle.SINGLE, size: 4, color: "000000" };
const BORDERS = { top: BORDER, bottom: BORDER, left: BORDER, right: BORDER };

function makeTable(rows) {
  const n = rows[0].length;
  const weights = new Array(n).fill(11);
  const minW = new Array(n).fill(0); // мінімальна ширина, щоб найдовше слово не переносилось
  rows.forEach((row) =>
    row.forEach((cell, i) => {
      const txt = unescape(cell.replace(/[`*]/g, ""));
      const longest = Math.max(...txt.split(/\s+/).map((w) => w.length), 0);
      const w = Math.max(Math.min(longest + 1, 24), 0.45 * Math.min(txt.length, 80), 11);
      if (w > weights[i]) weights[i] = w;
      const need = Math.min(longest, 22) * 150 + 260;
      if (need > minW[i]) minW[i] = need;
    })
  );
  const total = weights.reduce((a, b) => a + b, 0);
  let widths = weights.map((w) => (w / total) * TEXT_W);
  for (let k = 0; k < 5; k++) {
    const deficit = widths.reduce((a, w, j) => a + Math.max(0, minW[j] - w), 0);
    if (deficit <= 0) break;
    const spare = widths.reduce((a, w, j) => a + Math.max(0, w - minW[j]), 0);
    if (spare <= deficit) break;
    widths = widths.map((w, j) => (w < minW[j] ? minW[j] : w - (Math.max(0, w - minW[j]) / spare) * deficit));
  }
  widths = widths.map((w) => Math.floor(w));
  widths[n - 1] += TEXT_W - widths.reduce((a, b) => a + b, 0);
  return new Table({
    width: { size: TEXT_W, type: WidthType.DXA },
    columnWidths: widths,
    rows: rows.map((row, ri) =>
      new TableRow({
        tableHeader: ri === 0,
        cantSplit: true,
        children: row.map(
          (cell, ci) =>
            new TableCell({
              width: { size: widths[ci], type: WidthType.DXA },
              borders: BORDERS,
              verticalAlign: VerticalAlign.CENTER,
              margins: { top: 60, bottom: 60, left: 100, right: 100 },
              children: [
                new Paragraph({
                  alignment: ri === 0 ? AlignmentType.CENTER : AlignmentType.LEFT,
                  spacing: { line: 240 },
                  children: runs(cell, { size: 24, bold: ri === 0 }),
                }),
              ],
            })
        ),
      })
    ),
  });
}

function splitRow(line) {
  let s = line.trim();
  if (s.startsWith("|")) s = s.slice(1);
  if (s.endsWith("|")) s = s.slice(0, -1);
  return s.split(/(?<!\\)\|/).map((c) => c.trim());
}

// ---------- розбір markdown ----------
const lines = fs.readFileSync(MD, "utf8").split("\n");
let i = lines.findIndex((l) => l.startsWith("# Вступ"));
const body = [];
const bulletRef = "bul";
let numInstance = 0;

function flushPara(buf) {
  if (!buf.length) return;
  const text = buf.join(" ");
  const isTableCaption = /^Таблиця\s+\d/.test(text);
  const isSmallLead = false;
  body.push(
    new Paragraph({
      alignment: isTableCaption ? AlignmentType.LEFT : AlignmentType.JUSTIFIED,
      indent: { firstLine: IND },
      keepNext: isTableCaption,
      children: runs(isTableCaption ? text.replace(/^(Таблиця\s+[\d.]+[а-я]?)\s+—\s+/, "$1 - ") : text),
    })
  );
  buf.length = 0;
}

let para = [];
while (i < lines.length) {
  const line = lines[i];

  if (/^```/.test(line)) {
    flushPara(para);
    i++;
    const code = [];
    while (i < lines.length && !/^```/.test(lines[i])) code.push(lines[i++]);
    i++;
    code.forEach((cl, k) =>
      body.push(
        new Paragraph({
          spacing: { line: 240 },
          indent: { left: 200 },
          keepLines: true,
          children: [new TextRun({ text: cl.replace(/\t/g, "    ") || " ", font: MONO, size: 20 })],
        })
      )
    );
    body.push(new Paragraph({ spacing: { after: 120 }, children: [] }));
    continue;
  }

  if (/^#{1,2}\s/.test(line)) {
    flushPara(para);
    const level = line.startsWith("##") ? 2 : 1;
    const text = line.replace(/^#{1,2}\s+/, "").replace(/^Розділ\s+(\d)/, "$1");
    body.push(
      new Paragraph({
        heading: level === 1 ? HeadingLevel.HEADING_1 : HeadingLevel.HEADING_2,
        pageBreakBefore: body.length === 0 || (level === 1 && /^Додаток\s/.test(text)),
        children: runs(text.replace(/`/g, ""), { bold: false }),
      })
    );
    i++;
    continue;
  }

  if (/^\|/.test(line)) {
    flushPara(para);
    const rows = [];
    while (i < lines.length && /^\|/.test(lines[i])) {
      if (!/^\|\s*[-:]+\s*(\|\s*[-:]+\s*)*\|?\s*$/.test(lines[i])) rows.push(splitRow(lines[i]));
      i++;
    }
    body.push(makeTable(rows));
    body.push(new Paragraph({ spacing: { after: 120 }, children: [] }));
    continue;
  }

  const img = line.match(/^!\[(.*)\]\((.*)\)\s*$/);
  if (img) {
    flushPara(para);
    const file = path.join(HERE, img[2]);
    const buf = fs.readFileSync(file);
    const { w, h } = pngSize(buf);
    const targetW = Math.min(w, /dfd/.test(file) ? 640 : 600);
    body.push(
      new Paragraph({
        alignment: AlignmentType.CENTER,
        keepNext: true,
        spacing: { before: 120, after: 60, line: 240 },
        children: [new ImageRun({ type: "png", data: buf, transformation: { width: targetW, height: Math.round((h / w) * targetW) } })],
      })
    );
    body.push(
      new Paragraph({
        alignment: AlignmentType.CENTER,
        spacing: { after: 160 },
        children: runs(img[1].replace(/\s+[–—]\s+/, " - ")),
      })
    );
    i++;
    continue;
  }

  const bl = line.match(/^[-*]\s+(.*)$/);
  const nl = line.match(/^(\d+)\.\s+(.*)$/);
  if (bl || nl) {
    flushPara(para);
    const ordered = !!nl;
    const inst = ordered ? ++numInstance : 0;
    while (i < lines.length) {
      const m1 = lines[i].match(ordered ? /^\d+\.\s+(.*)$/ : /^[-*]\s+(.*)$/);
      if (!m1) break;
      let text = m1[1];
      i++;
      while (i < lines.length && /^\s{2,}\S/.test(lines[i])) text += " " + lines[i++].trim();
      if (!ordered && /^\*\*[^*]+\*\*/.test(text)) {
        body.push(new Paragraph({ alignment: AlignmentType.JUSTIFIED, indent: { firstLine: IND }, children: runs(text) }));
      } else {
        body.push(
          new Paragraph({
            alignment: /URL:|https?:\/\//.test(text) ? AlignmentType.LEFT : AlignmentType.JUSTIFIED,
            numbering: ordered ? { reference: "num", level: 0, instance: inst } : { reference: bulletRef, level: 0 },
            children: runs(text),
          })
        );
      }
    }
    continue;
  }

  if (/^\\(newpage|begin|end|tableofcontents)/.test(line) || /^\s*$/.test(line)) {
    flushPara(para);
    i++;
    continue;
  }

  para.push(line.trim());
  i++;
}
flushPara(para);

// ---------- документ ----------
const doc = new Document({
  creator: "Шульга Н.С.",
  title: "РГР. Аудит захищеності програмного застосунку",
  features: { updateFields: true },
  styles: {
    default: { document: { run: { font: FONT, size: 28 }, paragraph: { spacing: { line: 360 } } } },
    paragraphStyles: [
      {
        id: "Heading1", name: "Heading 1", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { font: FONT, size: 28, bold: false },
        paragraph: { spacing: { before: 120, after: 60, line: 360 }, indent: { firstLine: IND }, keepNext: true, outlineLevel: 0 },
      },
      {
        id: "Heading2", name: "Heading 2", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { font: FONT, size: 28, bold: false },
        paragraph: { spacing: { before: 60, after: 60, line: 360 }, indent: { firstLine: IND }, keepNext: true, outlineLevel: 1 },
      },
    ],
  },
  numbering: {
    config: [
      {
        reference: bulletRef,
        levels: [{ level: 0, format: LevelFormat.BULLET, text: "–", alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 0, firstLine: IND } } } }],
      },
      {
        reference: "num",
        levels: [{ level: 0, format: LevelFormat.DECIMAL, text: "%1.", alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 0, firstLine: IND } } } }],
      },
    ],
  },
  sections: [
    {
      properties: {
        titlePage: true,
        page: {
          size: { width: 11906, height: 16838 },
          margin: { top: 1134, bottom: 1134, left: 1417, right: 567, header: 567, footer: 567 },
        },
      },
      headers: {
        first: new Header({ children: [new Paragraph({ children: [] })] }),
        default: new Header({
          children: [
            new Paragraph({
              alignment: AlignmentType.RIGHT,
              spacing: { line: 240 },
              children: [new TextRun({ children: [PageNumber.CURRENT], font: FONT, size: 28 })],
            }),
          ],
        }),
      },
      children: [
        ...titlePage(),
        new Paragraph({ pageBreakBefore: true, alignment: AlignmentType.CENTER, spacing: { after: 160 }, children: [new TextRun({ text: "ЗМІСТ", font: FONT, size: 28 })] }),
        ...(staticToc() || [new TableOfContents("Зміст", { hyperlink: true, headingStyleRange: "1-2" })]),
        ...body,
      ],
    },
  ],
});

Packer.toBuffer(doc).then((b) => {
  fs.writeFileSync(OUT, b);
  console.log("OK", OUT, b.length);
});
