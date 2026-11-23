# -*- coding: utf-8 -*-
"""Минимальный генератор .docx (OOXML) без внешних зависимостей."""
import zipfile
from xml.sax.saxutils import escape

W = 'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"'
R = 'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"'


def _runs(text, bold=False, italic=False, font=None, sz=None, color=None):
    out = []
    for i, line in enumerate(str(text).split("\n")):
        rpr = ""
        if font: rpr += f'<w:rFonts w:ascii="{font}" w:hAnsi="{font}" w:cs="{font}"/>'
        if bold: rpr += "<w:b/>"
        if italic: rpr += "<w:i/>"
        if color: rpr += f'<w:color w:val="{color}"/>'
        if sz: rpr += f'<w:sz w:val="{sz}"/><w:szCs w:val="{sz}"/>'
        rpr = f"<w:rPr>{rpr}</w:rPr>" if rpr else ""
        br = "<w:br/>" if i else ""
        out.append(f'<w:r>{rpr}{br}<w:t xml:space="preserve">{escape(line)}</w:t></w:r>')
    return "".join(out)


def p(text="", style=None, bold=False, italic=False, align=None, font=None, sz=None,
      before=None, after=None, indent=None, first=None, line=None, keep=False, color=None):
    ppr = ""
    if style: ppr += f'<w:pStyle w:val="{style}"/>'
    if keep: ppr += "<w:keepNext/>"
    sp = ""
    if before is not None: sp += f' w:before="{before}"'
    if after is not None: sp += f' w:after="{after}"'
    if line is not None: sp += f' w:line="{line}" w:lineRule="auto"'
    if sp: ppr += f"<w:spacing{sp}/>"
    if indent is not None or first is not None:
        ind = ""
        if indent is not None: ind += f' w:left="{indent}"'
        if first is not None: ind += f' w:firstLine="{first}"'
        ppr += f"<w:ind{ind}/>"
    if align: ppr += f'<w:jc w:val="{align}"/>'
    ppr = f"<w:pPr>{ppr}</w:pPr>" if ppr else ""
    return f"<w:p>{ppr}{_runs(text, bold, italic, font, sz, color)}</w:p>"


def h1(text): return p(text, style="Heading1")
def h2(text): return p(text, style="Heading2")


def bullet(text, level=0):
    return p("– " + text, indent=709 + level * 360, first=-360, align="both", after=40)


def code(lines, sz=19):
    if isinstance(lines, str): lines = lines.split("\n")
    return "".join(p(l if l else " ", style="Code", sz=sz) for l in lines)


def table(headers, rows, widths, sz=22, header_sz=22):
    total = sum(widths)
    grid = "".join(f'<w:gridCol w:w="{w}"/>' for w in widths)
    borders = "".join(
        f'<w:{s} w:val="single" w:sz="4" w:space="0" w:color="808080"/>'
        for s in ("top", "left", "bottom", "right", "insideH", "insideV"))
    xml = [f'<w:tbl><w:tblPr><w:tblW w:w="{total}" w:type="dxa"/>'
           f'<w:tblBorders>{borders}</w:tblBorders>'
           f'<w:tblLayout w:type="fixed"/>'
           f'<w:tblCellMar><w:top w:w="60" w:type="dxa"/><w:left w:w="90" w:type="dxa"/>'
           f'<w:bottom w:w="60" w:type="dxa"/><w:right w:w="90" w:type="dxa"/></w:tblCellMar>'
           f'</w:tblPr><w:tblGrid>{grid}</w:tblGrid>']

    def row(cells, header=False):
        trpr = "<w:trPr><w:tblHeader/><w:cantSplit/></w:trPr>" if header else "<w:trPr><w:cantSplit/></w:trPr>"
        out = [f"<w:tr>{trpr}"]
        for c, w in zip(cells, widths):
            shd = '<w:shd w:val="clear" w:color="auto" w:fill="E9E9E9"/>' if header else ""
            out.append(f'<w:tc><w:tcPr><w:tcW w:w="{w}" w:type="dxa"/>{shd}'
                       f'<w:vAlign w:val="center"/></w:tcPr>')
            for j, part in enumerate(str(c).split("\n")):
                out.append(p(part, style="TableText", bold=header,
                             sz=header_sz if header else sz, align="left"))
            out.append("</w:tc>")
        out.append("</w:tr>")
        return "".join(out)

    if headers: xml.append(row(headers, header=True))
    for r in rows: xml.append(row(r))
    xml.append("</w:tbl>")
    xml.append(p("", after=0, line=240, sz=12))
    return "".join(xml)


WP = 'xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing"'
A = 'xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"'
PIC = 'xmlns:pic="http://schemas.openxmlformats.org/drawingml/2006/picture"'


def pic(rid: str, cx: int, cy: int, doc_pr_id: int = 1, name: str = "image") -> str:
    """Встроенное изображение (inline picture) шириной cx x cy в EMU."""
    return (
        f'<w:p><w:pPr><w:jc w:val="center"/><w:ind w:firstLine="0"/></w:pPr><w:r><w:drawing>'
        f'<wp:inline distT="0" distB="0" distL="0" distR="0" {WP}>'
        f'<wp:extent cx="{cx}" cy="{cy}"/>'
        f'<wp:docPr id="{doc_pr_id}" name="{escape(name)}"/>'
        f'<wp:cNvGraphicFramePr><a:graphicFrameLocks {A} noChangeAspect="1"/></wp:cNvGraphicFramePr>'
        f'<a:graphic {A}><a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/picture">'
        f'<pic:pic {PIC}>'
        f'<pic:nvPicPr><pic:cNvPr id="{doc_pr_id}" name="{escape(name)}"/><pic:cNvPicPr/></pic:nvPicPr>'
        f'<pic:blipFill><a:blip r:embed="{rid}"/><a:stretch><a:fillRect/></a:stretch></pic:blipFill>'
        f'<pic:spPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="{cx}" cy="{cy}"/></a:xfrm>'
        f'<a:prstGeom prst="rect"><a:avLst/></a:prstGeom></pic:spPr>'
        f'</pic:pic></a:graphicData></a:graphic></wp:inline></w:drawing></w:r></w:p>'
    )


def caption(text):
    return p(text, align="left", sz=24, before=120, after=60, first=0, italic=False)


def pagebreak():
    return '<w:p><w:r><w:br w:type="page"/></w:r></w:p>'


STYLES = f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:styles {W}>
<w:docDefaults><w:rPrDefault><w:rPr>
<w:rFonts w:ascii="Times New Roman" w:hAnsi="Times New Roman" w:cs="Times New Roman"/>
<w:sz w:val="28"/><w:szCs w:val="28"/><w:lang w:val="ru-RU"/>
</w:rPr></w:rPrDefault>
<w:pPrDefault><w:pPr><w:spacing w:after="0" w:line="360" w:lineRule="auto"/>
<w:ind w:firstLine="709"/><w:jc w:val="both"/></w:pPr></w:pPrDefault></w:docDefaults>
<w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/><w:qFormat/></w:style>
<w:style w:type="paragraph" w:styleId="Heading1"><w:name w:val="heading 1"/><w:basedOn w:val="Normal"/>
<w:next w:val="Normal"/><w:qFormat/><w:pPr><w:keepNext/><w:outlineLvl w:val="0"/>
<w:spacing w:before="280" w:after="140" w:line="360" w:lineRule="auto"/><w:ind w:firstLine="0"/>
<w:jc w:val="left"/></w:pPr><w:rPr><w:b/><w:sz w:val="28"/><w:szCs w:val="28"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Heading2"><w:name w:val="heading 2"/><w:basedOn w:val="Normal"/>
<w:next w:val="Normal"/><w:qFormat/><w:pPr><w:keepNext/><w:outlineLvl w:val="1"/>
<w:spacing w:before="200" w:after="100" w:line="360" w:lineRule="auto"/><w:ind w:firstLine="0"/>
<w:jc w:val="left"/></w:pPr><w:rPr><w:b/><w:sz w:val="28"/><w:szCs w:val="28"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="TableText"><w:name w:val="Table Text"/><w:basedOn w:val="Normal"/>
<w:pPr><w:spacing w:after="0" w:line="240" w:lineRule="auto"/><w:ind w:firstLine="0"/>
<w:jc w:val="left"/></w:pPr><w:rPr><w:sz w:val="22"/><w:szCs w:val="22"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Code"><w:name w:val="Code"/><w:basedOn w:val="Normal"/>
<w:pPr><w:spacing w:after="0" w:line="240" w:lineRule="auto"/><w:ind w:firstLine="0" w:left="284"/>
<w:jc w:val="left"/></w:pPr><w:rPr>
<w:rFonts w:ascii="Consolas" w:hAnsi="Consolas" w:cs="Consolas"/><w:sz w:val="19"/><w:szCs w:val="19"/>
</w:rPr></w:style>
</w:styles>'''

SECT = ('<w:sectPr><w:pgSz w:w="11906" w:h="16838"/>'
        '<w:pgMar w:top="1134" w:right="850" w:bottom="1134" w:left="1701" '
        'w:header="709" w:footer="709" w:gutter="0"/>'
        '<w:cols w:space="708"/><w:docGrid w:linePitch="360"/></w:sectPr>')


def save(path, body, title="Отчёт", media=None):
    doc = f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:document {W} {R}><w:body>{body}{SECT}</w:body></w:document>'
    ct = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Default Extension="png" ContentType="image/png"/>
<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
<Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>
<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>
<Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>
</Types>'''
    rels = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>
<Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/>
</Relationships>'''
    media = media or []
    drels_items = ['<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>']
    for rid, filename, _ in media:
        drels_items.append(f'<Relationship Id="{rid}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="media/{filename}"/>')
    drels = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
             '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
             + "".join(drels_items) + '</Relationships>')
    core = f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
 xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/"
 xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
<dc:title>{escape(title)}</dc:title><dc:creator>Михалёв Н. С.</dc:creator>
<cp:lastModifiedBy>Михалёв Н. С.</cp:lastModifiedBy>
<dcterms:created xsi:type="dcterms:W3CDTF">2026-11-15T09:00:00Z</dcterms:created>
<dcterms:modified xsi:type="dcterms:W3CDTF">2026-11-15T09:00:00Z</dcterms:modified>
</cp:coreProperties>'''
    app = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"
 xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes">
<Application>Microsoft Office Word</Application><AppVersion>16.0000</AppVersion></Properties>'''
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", ct)
        z.writestr("_rels/.rels", rels)
        z.writestr("word/document.xml", doc)
        z.writestr("word/styles.xml", STYLES)
        z.writestr("word/_rels/document.xml.rels", drels)
        z.writestr("docProps/core.xml", core)
        z.writestr("docProps/app.xml", app)
        for _, filename, data in media:
            z.writestr(f"word/media/{filename}", data)
    return path
